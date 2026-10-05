"""Secret redaction for PAN-OS configuration.

A firewall configuration holds administrator password hashes, pre-shared keys, SNMP communities, RADIUS/TACACS shared secrets,
private keys and tokens. Unlike the switch configs, these are redacted BY DEFAULT (set CONFIG_REDACT=false to turn it off).
Redaction is by element NAME, using the meaning of the name (anything with password, secret, community, psk, key and so on),
and is best-effort: a secret stored under an unexpected name can be missed, so the output is still sensitive."""
import os
import re

REDACTED = "REDACTED"
SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "community", "psk", "pre-shared", "phash", "token",
                "private-key", "privatekey", "credential", "authpwd", "privpwd", "master-key")
NOT_SECRET = {"key-size", "key-length", "key-usage", "keyword", "key-exchange", "key-lifetime", "key-type", "keyid"}
_ELEMENT = re.compile(r"<([A-Za-z][\w.-]*)(\s[^<>]*)?>([^<>]+)</\1>")
_PEM_RX = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S)


def is_secret_tag(tag: str) -> bool:
    t = tag.lower()
    if t in NOT_SECRET:
        return False
    if any(w in t for w in SECRET_WORDS):
        return True
    return t == "key" or t.endswith("-key") or t.endswith("_key")


def redaction_enabled() -> bool:
    return os.environ.get("CONFIG_REDACT", "true").strip().lower() not in ("0", "false", "no", "off")


def redact_xml_text(text: str) -> tuple[str, int]:
    count = [0]

    def sub(m):
        if is_secret_tag(m.group(1)) and m.group(3).strip() and m.group(3).strip() != REDACTED:
            count[0] += 1
            return f"<{m.group(1)}{m.group(2) or ''}>{REDACTED}</{m.group(1)}>"
        return m.group(0)

    out = _ELEMENT.sub(sub, text)

    def pem(m):
        count[0] += 1
        return "-----REDACTED KEY OR CERTIFICATE BLOCK-----"

    return _PEM_RX.sub(pem, out), count[0]


def redact_obj(obj, count=None):
    """Same idea for an already-parsed response (dicts and lists): values under secret-looking keys are replaced."""
    count = count if count is not None else [0]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and is_secret_tag(k) and isinstance(v, (str, int, float)) and str(v).strip() not in ("", REDACTED):
                out[k] = REDACTED
                count[0] += 1
            else:
                out[k] = redact_obj(v, count)
        return out
    if isinstance(obj, list):
        return [redact_obj(x, count) for x in obj]
    return obj


def redact_tree(root) -> int:
    """Redact an already-parsed config tree in place (same naming rules as redact_xml_text); returns how many values changed."""
    count = 0
    for el in root.iter():
        text = (el.text or "").strip()
        if not text or text == REDACTED:
            continue
        if is_secret_tag(el.tag):
            el.text, count = REDACTED, count + 1
        elif "-----BEGIN" in text:
            el.text, count = "-----REDACTED KEY OR CERTIFICATE BLOCK-----", count + 1
    return count
