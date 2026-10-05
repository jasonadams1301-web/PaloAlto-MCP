"""Safe XML helpers for the PAN-OS API.

Commands are BUILT as element trees (values go in as text and are escaped), never by formatting strings, so a value cannot
add or close elements. Responses are parsed with defusedxml (no DTDs, entities or external references) and converted to plain
Python data with size limits."""
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from defusedxml import ElementTree as SafeET

MAX_NODES = 300_000
MAX_DEPTH = 24


class XmlError(ValueError):
    pass


def build_command(path: tuple[str, ...], text: str | None = None, children: tuple[tuple[str, str], ...] = ()) -> str:
    """<a><b><c>text</c></b></a> from ("a","b","c"); `children` become sibling child elements of the last tag."""
    if not path:
        raise XmlError("empty command path")
    root = ET.Element(path[0])
    node = root
    for tag in path[1:]:
        node = ET.SubElement(node, tag)
    if text is not None:
        node.text = text
    for tag, value in children:
        ET.SubElement(node, tag).text = value
    return ET.tostring(root, encoding="unicode")


@dataclass
class Response:
    status: str
    code: str | None
    message: str
    result: ET.Element | None


def parse_response(text: str) -> Response:
    try:
        root = SafeET.fromstring(text, forbid_dtd=True)
    except Exception as e:                                              # noqa: BLE001
        raise XmlError(f"the device returned something that is not valid XML ({type(e).__name__})") from None
    if root.tag != "response":
        raise XmlError("unexpected response format")
    msg_el = root.find("msg")
    message = ""
    if msg_el is not None:
        lines = [(ln.text or "").strip() for ln in msg_el.iter("line")] or [(msg_el.text or "").strip()]
        message = " ".join(x for x in lines if x)
    res = root.find("result")
    if not message and res is not None and res.find("msg") is not None:
        message = " ".join((ln.text or "").strip() for ln in res.find("msg").iter("line")).strip()
    return Response(status=root.get("status", ""), code=root.get("code"), message=message, result=res)


def to_obj(el: ET.Element, _state=None, _depth=0):
    """XML element -> str | dict | list. <entry name=x> become dicts with a "name" key; wrappers that only hold
    <entry>/<member> children become lists."""
    state = _state if _state is not None else [0]
    state[0] += 1
    if state[0] > MAX_NODES or _depth > MAX_DEPTH:
        raise XmlError("response is too large or too deeply nested")
    kids = list(el)
    if not kids:
        text = (el.text or "").strip()
        return {"name": el.get("name"), "value": text} if (el.tag == "entry" and el.get("name") and text) else (
            {"name": el.get("name")} if el.tag == "entry" and el.get("name") else (text or None))
    tags = [k.tag for k in kids]
    if all(t in ("entry", "member") for t in tags) and len(set(tags)) == 1:
        return [to_obj(k, state, _depth + 1) for k in kids]
    out: dict = {}
    if el.tag == "entry" and el.get("name"):
        out["name"] = el.get("name")
    groups: dict[str, list] = {}
    for k in kids:
        groups.setdefault(k.tag, []).append(to_obj(k, state, _depth + 1))
    for tag, vals in groups.items():
        out[tag] = vals[0] if len(vals) == 1 else vals       # a repeated tag becomes a list (use as_list() when reading)
    return out


def dig(obj, *keys, default=None):
    """Safe nested lookup through dicts (and the first element of a list when the next key is a dict key)."""
    cur = obj
    for key in keys:
        if isinstance(cur, list) and cur and not isinstance(key, int):
            cur = cur[0]
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and isinstance(key, int) and -len(cur) <= key < len(cur):
            cur = cur[key]
        else:
            return default
        if cur is None:
            return default
    return cur


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
