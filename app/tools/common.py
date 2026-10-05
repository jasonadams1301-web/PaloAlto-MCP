"""Helpers shared by the tools."""
import re

from app.validation import Device, Inventory, ValidationError

LIMIT_MAX = 200
TEXT_FILTER = re.compile(r"[A-Za-z0-9 ._:/-]{1,64}")


def check_limit(limit, maximum: int = LIMIT_MAX) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= maximum:
        raise ValidationError(f"limit must be 1-{maximum}")
    return limit


def check_text(value, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not TEXT_FILTER.fullmatch(value):
        raise ValidationError(f"{label}: up to 64 letters, digits, space and . _ : / -")
    return value


def device_info(inv: Inventory, d: Device) -> dict:
    return {"device": d.name, "kind": d.kind, "managed_by": d.via}


def clip(rows: list, limit: int) -> tuple[list, str | None]:
    """First `limit` rows plus a note when some were cut."""
    if len(rows) <= limit:
        return rows, None
    return rows[:limit], f"{len(rows) - limit} more; narrow the filters or raise limit (max {LIMIT_MAX})"


def text_of(value) -> str:
    """A PAN-OS text result (for example top output) as a string, whatever shape it was parsed into."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def pick(entry, *keys):
    """Subset of an entry dict with just the keys that exist."""
    if not isinstance(entry, dict):
        return entry
    return {k: entry[k] for k in keys if k in entry}


def collect_entries(obj) -> list[dict]:
    """Every dict that looks like a table row, wherever it sits in a parsed response (lists of dicts, or an
    'entry' key). Layouts differ between PAN-OS versions and commands, so tools use this to stay tolerant."""
    rows: list[dict] = []

    def walk(o):
        if isinstance(o, list):
            if o and all(isinstance(x, dict) for x in o):
                rows.extend(x for x in o)
            else:
                for x in o:
                    walk(x)
        elif isinstance(o, dict):
            if "entry" in o:
                walk(o["entry"])
            else:
                for v in o.values():
                    if isinstance(v, (list, dict)):
                        walk(v)
    walk(obj)
    return rows


def num(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        try:
            return float(str(value).strip())
        except (TypeError, ValueError):
            return None
