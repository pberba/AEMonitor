from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------
# Low-level helpers
# ----------------------------


def decode_utxt_raw(raw: str) -> str:
    _length, _hex = raw.split("/$")
    return bytes.fromhex(_hex.strip(".")).decode("utf-16le", errors="replace")


def find_matching(s: str, i: int, open_ch: str, close_ch: str) -> int:
    """Quote/escape-aware matching for (), [], {}, <> starting at s[i] == open_ch. Returns index or -1."""
    if i >= len(s) or s[i] != open_ch:
        return -1

    depth = 0
    in_single = False
    in_double = False
    esc = False

    j = i
    while j < len(s):
        ch = s[j]

        if in_single or in_double:
            if esc:
                esc = False
            else:
                if ch == "\\":
                    esc = True
                elif in_single and ch == "'":
                    in_single = False
                elif in_double and ch == '"':
                    in_double = False
            j += 1
            continue

        if ch == "'":
            in_single = True
            j += 1
            continue
        if ch == '"':
            in_double = True
            j += 1
            continue

        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return j

        j += 1

    return -1


def looks_like_key_start(s: str, i: int) -> bool:
    """
    Heuristic: at s[i], do we appear to be at the start of `key=` or `key:` ?

    IMPORTANT FIX:
    If the next non-space char begins a value (quote / brace / bracket / paren),
    it is NOT a key start. This prevents URLs like "file:///..." being mistaken
    for `"file":///...`.
    """
    n = len(s)
    j = i
    while j < n and s[j].isspace():
        j += 1
    if j >= n or s[j] in "}]":
        return False

    # If it looks like the start of a value, it's not a key.
    if s[j] in ('"', "'", "{", "[", "("):
        return False

    # Read a potential key token
    k = j
    while k < n and s[k] not in " \t\r\n=,:{}[]()":
        k += 1
    if k == j:
        return False

    t = k
    while t < n and s[t].isspace():
        t += 1

    return t < n and s[t] in ("=", ":")


def bracket_is_list(s: str, i: int) -> bool:
    end = find_matching(s, i, "[", "]")
    if end == -1:
        return True
    inner = s[i + 1 : end].strip()
    return not inner or "," in inner or "(" in inner or "{" in inner


# ----------------------------
# Parser
# ----------------------------


@dataclass
class Parser:
    s: str
    i: int = 0

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def peek(self) -> str:
        return self.s[self.i] if not self.eof() else ""

    def skip_ws(self) -> None:
        while not self.eof() and self.s[self.i].isspace():
            self.i += 1

    def consume(self, ch: str) -> None:
        if self.peek() != ch:
            raise ValueError(f"Expected '{ch}' at {self.i}, got '{self.peek()}'")
        self.i += 1

    def read_while(self, pred) -> str:
        start = self.i
        while not self.eof() and pred(self.s[self.i]):
            self.i += 1
        return self.s[start : self.i]

    def _advance_if_stuck(self, before: int) -> None:
        if self.i == before:
            self.i += 1

    # Values may contain ':' (URLs like file:///...), so ':' must NOT be a separator here.
    def read_ident(self) -> str:
        return self.read_while(lambda c: c not in " \t\r\n=,{}[]()")

    # Keys can be followed by ':' (attr:{...}), so ':' stays a separator for keys.
    def read_key(self) -> str:
        self.skip_ws()
        return self.read_while(lambda c: c not in " \t\r\n=,{}[]():")

    def read_quoted(self) -> str:
        quote = self.peek()
        self.i += 1
        out: List[str] = []
        esc = False
        while not self.eof():
            ch = self.s[self.i]
            self.i += 1
            if esc:
                out.append(ch)
                esc = False
            else:
                if ch == "\\":
                    esc = True
                elif ch == quote:
                    break
                else:
                    out.append(ch)
        return "".join(out)

    def read_paren_group_raw(self) -> Dict[str, str]:
        """Read a (...) group as raw text (e.g. (sandboxAnnotation, len=...))."""
        start = self.i
        end = find_matching(self.s, self.i, "(", ")")
        if end == -1:
            self.i = len(self.s)
            return {"__paren__": self.s[start:]}
        inner = self.s[self.i + 1 : end]
        self.i = end + 1
        return {"__paren__": inner}

    def read_typed_parens_raw(self, type_name: str) -> Dict[str, Any]:
        """Read type_name(...) as raw inner string."""
        start = self.i
        end = find_matching(self.s, self.i, "(", ")")
        if end == -1:
            self.i = len(self.s)
            inner = self.s[start + 1 :].strip()
        else:
            inner = self.s[start + 1 : end].strip()
            self.i = end + 1
        return {"__type__": type_name, "__raw__": inner}

    def read_bracket_token(self) -> Dict[str, str]:
        """Read [Finder] / [osascript] as a token."""
        start = self.i
        end = find_matching(self.s, self.i, "[", "]")
        if end == -1:
            self.i = len(self.s)
            return {"__bracket__": self.s[start:]}
        inner = self.s[self.i + 1 : end]
        self.i = end + 1
        return {"__bracket__": inner}

    def read_list(self) -> List[Any]:
        """Read a list value like [utxt(...), ...] or [(sandboxAnnotation,...), ...]."""
        self.consume("[")
        items: List[Any] = []
        self.skip_ws()
        while not self.eof() and self.peek() != "]":
            before = self.i
            items.append(self.read_value_part())
            self.skip_ws()
            if self.peek() == ",":
                self.consume(",")
                self.skip_ws()
            self._advance_if_stuck(before)
        if self.peek() == "]":
            self.consume("]")
        return items

    def read_value_part(self) -> Any:
        """Read one atomic value part."""
        self.skip_ws()
        ch = self.peek()

        if ch == "{":
            return self.read_brace_object()
        if ch == "[":
            if bracket_is_list(self.s, self.i):
                return self.read_list()
            return self.read_bracket_token()
        if ch == "(":
            return self.read_paren_group_raw()
        if ch in ("'", '"'):
            return self.read_quoted()

        token = self.read_ident()
        self.skip_ws()

        if token == "":
            if not self.eof():
                self.i += 1
            return ""

        if token and self.peek() == "(":
            return self.read_typed_parens_raw(token)

        if token.lstrip("-").isdigit():
            return int(token)

        if token == "true":
            return True
        if token == "false":
            return False

        return token

    def read_value_sequence(self) -> Any:
        """
        Read one or more adjacent value parts for a single key=...
        Needed for: target='psn '[Finder] {....}
        """
        parts: List[Any] = []
        self.skip_ws()
        while not self.eof():
            self.skip_ws()
            if self.peek() in ("}", ","):
                break
            if looks_like_key_start(self.s, self.i):
                break
            before = self.i
            parts.append(self.read_value_part())
            self._advance_if_stuck(before)
        if not parts:
            return None
        return parts[0] if len(parts) == 1 else parts

    def read_brace_object(self) -> Dict[str, Any]:
        """Parse {...} objects, including optional AppleEvent header class,id."""
        self.consume("{")
        self.skip_ws()

        obj: Dict[str, Any] = {}

        # Optional header "class,id" — only for top-level AppleEvent-like objects
        save = self.i
        first = self.read_key()
        if first and self.peek() == ",":
            self.consume(",")
            second = self.read_key()
            obj["__event__"] = {"class": first, "id": second}
        else:
            self.i = save

        self.skip_ws()

        while not self.eof() and self.peek() != "}":
            self.skip_ws()
            if self.peek() == ",":
                self.consume(",")
                continue

            before_loop = self.i

            key = self.read_key().strip()
            self.skip_ws()

            if key == "":
                if not self.eof():
                    self.i += 1
                continue

            if self.peek() == ":":
                # attr:{...} form
                self.consume(":")
                self.skip_ws()
                obj[key] = self.read_value_part()
            elif self.peek() == "=":
                self.consume("=")
                obj[key] = self.read_value_sequence()
            else:
                obj.setdefault("__items__", []).append(key)

            self.skip_ws()
            if self.peek() == ",":
                self.consume(",")

            self._advance_if_stuck(before_loop)

        if self.peek() == "}":
            self.consume("}")
        return obj


def parse_apple_event_debug(s: str) -> Dict[str, Any]:
    p = Parser(s)
    p.skip_ws()
    v = p.read_value_part()
    if not isinstance(v, dict):
        raise ValueError("Expected top-level {...}")
    p.skip_ws()
    if not p.eof():
        v["__trailing__"] = p.s[p.i :].strip()
    return split_target_and_params(v)


# ----------------------------
# Normalize: split target / params
# ----------------------------


def _brace_obj_has_params_marker(x: Any) -> bool:
    return isinstance(x, dict) and "----" in x


def _is_typed_value(x: Any) -> bool:
    return isinstance(x, dict) and "__type__" in x


def _find_params_and_first_typed(
    rest: List[Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Returns (params_obj, first_typed)."""
    params_obj = None
    first_typed = None
    last_typed = None
    for part in rest:
        if isinstance(part, dict):
            if _brace_obj_has_params_marker(part):
                return (part, first_typed)
            if _is_typed_value(part):
                if first_typed is None:
                    first_typed = part
                last_typed = part
            elif params_obj is None:
                params_obj = part  # e.g. {errn=-1708} or {prdt=..., aapd=...}
    return (params_obj if params_obj is not None else last_typed, first_typed)


def split_target_and_params(
    parsed: Dict[str, Any], params_only_direct_object: bool = False
) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    ev = parsed.get("__event__", {})
    out["event_class"] = ev.get("class")
    out["event_id"] = ev.get("id")
    out["attr"] = parsed.get("attr")
    out["return_id"] = parsed.get("returnID", "UNKNOWN")

    target_raw = parsed.get("target")
    params_obj: Optional[Dict[str, Any]] = None

    if isinstance(target_raw, list):
        psn = None
        app = None
        rest: List[Any] = []
        for part in target_raw:
            if isinstance(part, str) and psn is None:
                psn = part
            elif isinstance(part, dict) and "__bracket__" in part and app is None:
                app = part["__bracket__"]
            else:
                rest.append(part)

        params_obj, first_typed = _find_params_and_first_typed(rest)
        out["target"] = app if app is not None else psn
        if (
            out["target"] is None
            and first_typed
            and first_typed.get("__type__") == "port"
        ):
            out["_target_port"] = True

    elif isinstance(target_raw, str):
        out["target"] = target_raw
        params_obj, _ = _find_params_and_first_typed(parsed.get("__items__", []))
    else:
        out["target"] = target_raw

    out["params"] = (
        params_obj.get("----")
        if (params_only_direct_object and isinstance(params_obj, dict))
        else params_obj
    )
    return out
