"""PAN-OS XML API client (read-only).

- The API key travels in the X-PAN-KEY header, never in the URL, and is never logged or returned.
- TLS is always verified. Management certificates are often self-signed, so a device is normally PINNED: its own certificate
  (collected once with scan-cert.py and approved by a person) is the only trust anchor. Otherwise normal CA verification.
- A firewall managed by Panorama is queried THROUGH Panorama (target=<serial>), using Panorama's address, certificate and key.
- Only requests built from the fixed tables in app/commands.py can be made."""
import asyncio
import os
import ssl
import time

import httpx

from app.commands import build_op, build_xpath
from app.secrets import get_secret
from app.validation import Device, Inventory
from app.xmlutil import XmlError, parse_response, to_obj


LOGIN_BACKOFF_SECONDS = 300


class PanosError(RuntimeError):
    pass


class _Rejected(Exception):
    """The device answered 401/403 (internal; turned into a PanosError or a one-time re-login)."""


def _tls_failure(e: Exception) -> bool:
    """httpx wraps TLS errors in ConnectError, so look at the cause chain."""
    while e is not None:
        if isinstance(e, ssl.SSLError):
            return True
        e = e.__cause__ or e.__context__
    return False


def _tls_message(name: str, e: Exception) -> str:
    detail = str(e)
    c = e
    while c is not None and not isinstance(c, ssl.SSLError):
        c = c.__cause__ or c.__context__
    detail = str(c) if c is not None else detail
    if "unsuitable certificate purpose" in detail:
        return (f"TLS verification failed for {name}: the pinned certificate is a CA-only certificate and cannot be used "
                f"as a server certificate (generate it without 'Certificate Authority' ticked)")
    if "CERTIFICATE_VERIFY_FAILED" in detail:
        return f"TLS verification failed for {name} (certificate does not match the pinned one)"
    return f"TLS error for {name} ({type(c or e).__name__})"


def cert_path(endpoint: Device, cert_dir: str) -> str:
    return os.path.join(cert_dir, f"{endpoint.name}.pem")


def pinned_context(cafile: str | None = None, cadata: str | None = None) -> ssl.SSLContext:
    """A TLS context whose only trust anchor is the given certificate (a self-signed management certificate)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False                       # the pinned certificate is the identity, not the name
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)    # allow a self-signed leaf as the trust anchor
    ctx.load_verify_locations(cafile=cafile, cadata=cadata)
    return ctx


def make_ssl_context(endpoint: Device, cert_dir: str, ca_bundle: str | None) -> ssl.SSLContext:
    if endpoint.tls == "ca":
        return ssl.create_default_context(cafile=ca_bundle or None)
    pem = cert_path(endpoint, cert_dir)
    if not os.path.isfile(pem):
        raise PanosError(f"no pinned certificate for {endpoint.name}; collect it with scan-cert.py and review the "
                         f"fingerprint before approving it")
    return pinned_context(cafile=pem)


class PanosClient:
    def __init__(self, inv: Inventory, transport: httpx.AsyncBaseTransport | None = None):
        self.inv = inv
        self.transport = transport                                      # tests inject a fake device here
        self.cert_dir = os.environ.get("PANOS_CERT_DIR", "/etc/paloalto-mcp/certs")
        self.ca_bundle = os.environ.get("PANOS_CA_BUNDLE") or None
        self.timeout = float(os.environ.get("PANOS_TIMEOUT_SECONDS", "30"))
        self.max_bytes = int(os.environ.get("PANOS_MAX_RESPONSE_BYTES", str(30_000_000)))
        self.sem = asyncio.Semaphore(int(os.environ.get("PANOS_MAX_PARALLEL", "6")))
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._keys: dict[str, str] = {}                                 # keys obtained by logging in
        self._key_lock = asyncio.Lock()
        self._refused: dict[str, tuple[float, str]] = {}                # endpoint -> (retry after, message)

    # ---------------- plumbing ----------------
    async def _api_key(self, endpoint: Device, refresh: bool = False) -> str:
        """A configured API key if there is one, otherwise a key obtained by logging in (keygen) with the read-only
        account's username and password. The generated key is kept in memory only; the password is sent once per
        key, in the request body, and is never logged or returned."""
        suffix = (endpoint.credential or endpoint.kind).upper()
        key = get_secret("PANOS_KEY_" + suffix)
        if key:
            return key
        user, password = get_secret("PANOS_USER_" + suffix), get_secret("PANOS_PASS_" + suffix)
        if not (user and password):
            raise PanosError(f"no credentials are configured for {endpoint.name} (panos_user_{suffix.lower()} and "
                             f"panos_pass_{suffix.lower()}, or panos_key_{suffix.lower()})")
        if refresh:
            self._keys.pop(endpoint.name, None)
        if endpoint.name not in self._keys:
            refused = self._refused.get(endpoint.name)
            if refused and time.monotonic() < refused[0]:
                raise PanosError(refused[1] + f" (not retrying for {int(refused[0] - time.monotonic())} s, to avoid locking the account)")
            async with self._key_lock:
                if endpoint.name not in self._keys:
                    try:
                        self._keys[endpoint.name] = await self._login(endpoint, user, password)
                        self._refused.pop(endpoint.name, None)
                    except PanosError as e:
                        if "was refused" in str(e):                    # only a real refusal; network errors may retry at once
                            self._refused[endpoint.name] = (time.monotonic() + LOGIN_BACKOFF_SECONDS, str(e))
                        raise
        return self._keys[endpoint.name]

    async def _login(self, endpoint: Device, user: str, password: str) -> str:
        try:
            async with self.sem:
                r = await self._client(endpoint).post(f"https://{endpoint.address}/api/",
                                                      data={"type": "keygen", "user": user, "password": password})
        except httpx.HTTPError as e:
            raise PanosError(_tls_message(endpoint.name, e) if _tls_failure(e)
                             else f"could not reach {endpoint.name} ({type(e).__name__})") from None
        try:
            resp = parse_response(r.text)
        except XmlError:
            raise PanosError(f"login to {endpoint.name} failed (HTTP {r.status_code})") from None
        obj = to_obj(resp.result) if resp.result is not None else None
        key = obj.get("key") if isinstance(obj, dict) else None
        if resp.status != "success" or not key:
            said = str(resp.message or (obj.get("msg") if isinstance(obj, dict) else "") or "")
            said = said.replace(password, "***").replace(user, "***")[:160]
            raise PanosError(f"login to {endpoint.name} was refused" + (f" ({said})" if said else "") +
                             "; check the read-only account's username, password and that it may use the XML API")
        return str(key)

    def _client(self, endpoint: Device) -> httpx.AsyncClient:
        c = self._clients.get(endpoint.name)
        if c is None:
            if self.transport is not None:
                c = httpx.AsyncClient(transport=self.transport, timeout=self.timeout)
            else:
                c = httpx.AsyncClient(verify=make_ssl_context(endpoint, self.cert_dir, self.ca_bundle),
                                      timeout=self.timeout, follow_redirects=False)
            self._clients[endpoint.name] = c
        return c

    async def _post(self, device: Device, data: dict, _retry: bool = True) -> str:
        endpoint = self.inv.endpoint(device)
        key = await self._api_key(endpoint)
        payload = dict(data)
        if device.via:
            payload["target"] = device.serial
        url = f"https://{endpoint.address}/api/"
        try:
            async with self.sem:
                async with self._client(endpoint).stream("POST", url, data=payload, headers={"X-PAN-KEY": key}) as r:
                    if r.status_code in (401, 403):
                        raise _Rejected()
                    if r.status_code >= 400:
                        raise PanosError(f"the device returned HTTP {r.status_code}")
                    body, size = [], 0
                    async for chunk in r.aiter_bytes():
                        size += len(chunk)
                        if size > self.max_bytes:
                            raise PanosError("response too large; narrow the request")
                        body.append(chunk)
        except _Rejected:
            if _retry and endpoint.name in self._keys:                      # a login key can expire: log in again once
                self._keys.pop(endpoint.name, None)
                return await self._post(device, data, _retry=False)
            raise PanosError("the device rejected the credentials or the account's role lacks permission") from None
        except PanosError:
            raise
        except httpx.HTTPError as e:
            raise PanosError(_tls_message(endpoint.name, e) if _tls_failure(e)
                             else f"could not reach {endpoint.name} ({type(e).__name__})") from None
        return b"".join(body).decode("utf-8", errors="replace")

    async def _api(self, device: Device, data: dict):
        text = await self._post(device, data)
        try:
            resp = parse_response(text)
        except XmlError as e:
            raise PanosError(str(e)) from None
        if resp.status != "success":
            raise PanosError(f"the device reported an error: {resp.message or 'unknown'}"
                             + (f" (code {resp.code})" if resp.code else ""))
        return resp

    # ---------------- requests ----------------
    async def op(self, device: Device, key: str, **params):
        """Run a fixed operational command; returns the parsed <result> (dict, list, text or None)."""
        resp = await self._api(device, {"type": "op", "cmd": build_op(key, **params)})
        return to_obj(resp.result) if resp.result is not None else None

    async def config_get(self, device: Device, section: str, *, vsys: str | None = None, dg: str | None = None):
        xpath = build_xpath(section, vsys or device.vsys, dg)
        resp = await self._api(device, {"type": "config", "action": "get", "xpath": xpath})
        return to_obj(resp.result) if resp.result is not None else None

    async def export_config(self, device: Device) -> str:
        """The running configuration as XML text (type=export; read-only)."""
        text = await self._post(device, {"type": "export", "category": "configuration"})
        if text.lstrip().startswith("<response") and 'status="error"' in text[:200]:
            await self._api_error(text)
        return text

    async def _api_error(self, text: str):
        resp = parse_response(text)
        raise PanosError(f"the device reported an error: {resp.message or 'unknown'}")

    async def log_search(self, device: Device, log_type: str, query: str, nlogs: int, max_wait: float = 45.0) -> list:
        """Start a log query job and poll until it finishes. Returns the log entries (list of dicts)."""
        start = await self._api(device, {"type": "log", "log-type": log_type, "query": query, "nlogs": str(nlogs),
                                         "skip": "0"})
        job = to_obj(start.result).get("job") if isinstance(to_obj(start.result), dict) else None
        if not job:
            raise PanosError("the device did not start a log search job")
        deadline = time.monotonic() + max_wait
        delay = 0.4
        while True:
            resp = await self._api(device, {"type": "log", "action": "get", "job-id": str(job)})
            obj = to_obj(resp.result) if resp.result is not None else {}
            status = (obj.get("job") or {}).get("status") if isinstance(obj, dict) else None
            if status == "FIN":
                logs = ((obj.get("log") or {}).get("logs") or {}) if isinstance(obj, dict) else {}
                entries = logs.get("entry") if isinstance(logs, dict) else logs
                if entries is None:
                    return []
                return entries if isinstance(entries, list) else [entries]
            if time.monotonic() > deadline:
                raise PanosError("the log search did not finish in time; narrow the time window or add a filter")
            await asyncio.sleep(delay)
            delay = min(delay * 1.6, 2.5)
