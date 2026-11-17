import logging
import re
from applescript_decompiler.ast import (
    BinaryOp,
    BinaryOpKind,
    CommandCall,
    Keyword,
    ListLiteral,
    NumberLiteral,
    RecordField,
    RecordLiteral,
    StringLiteral,
    VariableRef,
)


def get_command_name(event):
    return f'{event["event_class"]}{event["event_id"]}'


def get_target(event):
    if event["target"] is None:
        # Port targets use UNKNOWN for display
        if event.get("_target_port"):
            return VariableRef(name="UNKNOWN")
        return None
    return VariableRef(name=event["target"])


def get_expression(expr):
    # It's short, it's probably an Apple term
    if isinstance(expr, str):
        if len(expr) > 8:
            return StringLiteral(expr)
        return Keyword(expr)
    if isinstance(expr, int):
        return NumberLiteral(expr)
    if isinstance(expr, list):
        return ListLiteral([get_expression(e) for e in expr])
    if "__type__" not in expr and "want" in expr and "seld" in expr and "from" in expr:
        # likely the form, want, seld, from
        if expr["want"] != "prop":
            indexed = BinaryOp(
                op=BinaryOpKind.GET_INDEXED,
                left=get_expression(expr["want"]),
                right=get_expression(expr["seld"]),
            )
        else:
            indexed = get_expression(expr["seld"])
        if expr["from"] is not None and expr["from"] != "NULL-impl":
            return BinaryOp(
                op=BinaryOpKind.GET_PROPERTY,
                left=indexed,
                right=get_expression(expr["from"]),
            )
        return indexed
    if "__type__" in expr and expr["__type__"] == "utxt":
        # raw is <length>/$<first 32 bytes>...
        _length, _hex = expr["__raw__"].split("/$")
        _hex_bytes = bytes.fromhex(_hex.strip("."))
        try:
            _hex_value = _hex_bytes.decode("utf-16le")
        except UnicodeDecodeError:
            # Truncated/corrupt hex (e.g. utxt(6/$74006d0000) has odd bytes) - use replace for robustness
            logging.warning(f"Truncated/corrupt hex: {_hex}")
            _hex_value = _hex_bytes.decode("utf-16le", errors="replace")
        if int(_length) > 16 * 2:
            return StringLiteral(f"{_hex_value}...")
        return StringLiteral(_hex_value)
    if "__type__" in expr and expr["__type__"] == "abso":
        # raw is <length>/$<hex bytes>, reversed and decoded as ASCII (e.g. abso(4/$206c6c61) -> "all ")
        _length, _hex = expr["__raw__"].split("/$")
        _hex_bytes = bytes.fromhex(_hex.strip("."))
        _reversed = _hex_bytes[::-1].decode("ascii")
        return StringLiteral(_reversed)
    if "__type__" in expr and (expr["__type__"] == "fals" or expr["__type__"] == "true"):
        return Keyword(expr["__type__"])
    
    if "__type__" in expr:
        logging.warning(f"NOT IMPLEMENTED: {expr}")
        return StringLiteral(f"{expr['__type__']}({expr['__raw__']})")

    # Assume it is a record literal ???
    records = []
    for k, v in expr.items():
        records.append(RecordField(label=Keyword(k), value=get_expression(v)))
    return RecordLiteral(fields=records)


def get_arguments(event):
    ret = []
    # The direct parameter "----" should go first
    if "----" in event["params"]:
        ret.append(get_expression(event["params"]["----"]))
    for k, v in event["params"].items():
        if "---" in k:
            continue
        if not isinstance(v, dict) and not isinstance(v, list):
            ret.append(Keyword(k))
            ret.append(get_expression(str(v)))
        elif k == "data":
            ret.append(Keyword(k))
            ret.append(get_expression(v))
        # fals and true are special cases since they change the
        # way that the params are presented
        elif "__type__" in v and v["__type__"] == "fals":
            ret.append(Keyword("without"))
            ret.append(Keyword(k))
        elif "__type__" in v and v["__type__"] == "true":
            ret.append(Keyword(k))
        else:
            ret.append(Keyword(k))
            ret.append(get_expression(v))
    return ret


# aevt/ansr is the standard Apple Event "answer" (a reply), not a command. The
# decompiler has no terminology for it, so rendering it as a command produced a
# bogus "aevtansr ..." statement (e.g. tell application "X" aevtansr {...}); for a
# reply we want just the answer value instead.
ANSWER_EVENT = ("aevt", "ansr")


def _derive_answer_value(event):
    params = event.get("params") or {}
    if "----" in params:
        node = get_expression(params["----"])
    else:
        fields = [
            RecordField(label=Keyword(k), value=get_expression(v))
            for k, v in params.items()
            if "---" not in k
        ]
        if not fields:
            return ""
        node = RecordLiteral(fields=fields)
    source = node.to_source()
    # CommandCall.to_source wraps in parens; a bare expression usually doesn't, but
    # strip a matching outer pair (e.g. a parenthesized object spec) if present.
    if source.startswith("(") and source.endswith(")"):
        source = source[1:-1]
    return source


def derive_ast(event, omit_target=False):
    if (event.get("event_class"), event.get("event_id")) == ANSWER_EVENT:
        return _derive_answer_value(event)
    source = CommandCall(
        target=get_target(event),
        command_name=get_command_name(event),
        arguments=get_arguments(event),
    ).to_source()[1:-1]
    if omit_target:
        # The target is kept so the decompiler can resolve the app's terminology
        # (command codes like coredosc -> "do script" via SDEFS[target]); drop the now
        # redundant "tell application X" prefix it produced.
        source = re.sub(r'^tell application "[^"]*" ', "", source, count=1)
    return source
