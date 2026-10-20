"""Masking one SQL write so only declared columns show their values.

The trace hook hands us each statement as SQLite ran it (with its values filled in on Python 3.11+; as written, with
`?`, on older versions). This reads the four write shapes an app makes, works out which column every literal belongs
to, and keeps a literal only when that column is declared loggable. Everything it can't place is masked: an unknown
table, an undeclared column, a subquery, a statement shape it doesn't know. Masking too much is a nuisance; masking too
little is a leak.

    mask("UPDATE users SET pass_hash='x' WHERE username='j'", rules)
      -> "UPDATE users SET pass_hash=? WHERE username='j'"     (pass_hash secret, username loggable)
"""
import re

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>--[^\n]*|/\*.*?\*/)
  | (?P<str>'(?:[^']|'')*'?)
  | (?P<blob>[xX]'[0-9a-fA-F]*'?)
  | (?P<num>(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<qid>"(?:[^"]|"")*"?|`[^`]*`?|\[[^\]]*\]?)
  | (?P<id>[A-Za-z_][A-Za-z0-9_$]*)
  | (?P<param>[?:@$][A-Za-z0-9_]*)
  | (?P<op><>|!=|<=|>=|==|\|\||<<|>>|.)
""", re.X | re.S)

WRITES = ("INSERT", "REPLACE", "UPDATE", "DELETE")
_COMPARE = {"=", "==", "<", ">", "<=", ">=", "!=", "<>", "IS", "IN", "LIKE", "GLOB", "BETWEEN", "NOT", "MATCH"}
_RESET = {"AND", "OR", "WHERE", "SET", "RETURNING", "ORDER", "LIMIT", "ON", "DO", "FROM"}
MASK = "?"


class Token:
    __slots__ = ("kind", "text", "up")

    def __init__(self, kind, text):
        self.kind, self.text = kind, text
        self.up = text.upper() if kind == "id" else text


def tokens(sql):
    out = []
    for m in _TOKEN.finditer(sql):
        kind = m.lastgroup
        out.append(Token(kind, m.group()))
    return out


def _name(t):
    if t.kind == "qid":
        return t.text[1:-1].replace('""', '"')
    return t.text


def _literal(t):
    return t.kind in ("str", "blob", "num")


class Rules:
    """What may be shown. columns: {table: set of loggable columns}. secret_tables: statements on them are reduced to
    their verb and table. secret_rows: {table: (key_column, {key values})}: a statement that names one of those keys
    (settings' 'webull_token') shows only the key. columns_of(table): the table's columns in order, for an INSERT
    without a column list. scrub: values that must never appear, whatever column they're in."""

    def __init__(self, columns=None, secret_tables=(), secret_rows=None, columns_of=None, scrub=(),
                 secret_columns=None):
        self.columns = {t.lower(): {c.lower() for c in cs} for t, cs in (columns or {}).items()}
        self.secret_columns = {t.lower(): {c.lower() for c in cs} for t, cs in (secret_columns or {}).items()}
        self.secret_tables = {t.lower() for t in secret_tables}
        self.secret_rows = {t.lower(): (k.lower(), set(v)) for t, (k, v) in (secret_rows or {}).items()}
        self.columns_of = columns_of
        self.scrub = [s for s in scrub if s]
        self.undeclared = set()  # (table, column or None) seen and masked for want of a declaration

    def allowed(self, table, column):
        return column is not None and column in self.columns.get(table, ())


def verb_and_table(toks):
    """('INSERT', 'txns', index after the table name) or (None, None, 0)."""
    words = [i for i, t in enumerate(toks) if t.kind not in ("ws", "comment")]
    if not words:
        return None, None, 0
    first = toks[words[0]].up
    if first not in WRITES:
        return None, None, 0
    j = 1
    def word(k):
        return toks[words[k]].up if k < len(words) else ""
    if first == "INSERT" and word(j) == "OR":
        j += 2
    if first == "UPDATE" and word(j) == "OR":
        j += 2
    if first in ("INSERT", "REPLACE"):
        if word(j) != "INTO":
            return first, None, 0
        j += 1
    if first == "DELETE":
        if word(j) != "FROM":
            return first, None, 0
        j += 1
    if j >= len(words):
        return first, None, 0
    k = words[j]
    if toks[k].kind not in ("id", "qid"):
        return first, None, 0
    name = _name(toks[k])
    # schema.table
    if j + 2 < len(words) and toks[words[j + 1]].text == "." and toks[words[j + 2]].kind in ("id", "qid"):
        name, k = _name(toks[words[j + 2]]), words[j + 2]
    return first, name.lower(), k + 1


def place(toks, verb, table, start, rules):
    """For each literal token index, the column it belongs to (or None)."""
    owner = {}
    sig = [i for i in range(start, len(toks)) if toks[i].kind not in ("ws", "comment")]
    n = len(sig)
    p = 0
    insert_cols = None

    def at(k):
        return toks[sig[k]] if k < n else None

    if verb in ("INSERT", "REPLACE"):
        if at(p) and at(p).text == "(":
            cols, p = [], p + 1
            while p < n and at(p).text != ")":
                if at(p).kind in ("id", "qid"):
                    cols.append(_name(at(p)).lower())
                p += 1
            p += 1
            insert_cols = cols
        elif rules.columns_of:
            insert_cols = [c.lower() for c in (rules.columns_of(table) or [])]
        if at(p) and at(p).up == "VALUES":
            p += 1
            depth, pos = 0, 0
            while p < n:
                t = at(p)
                if t.text == "(":
                    depth += 1
                    if depth == 1:
                        pos = 0
                elif t.text == ")":
                    depth -= 1
                elif t.text == "," and depth == 1:
                    pos += 1
                elif depth == 0 and t.kind == "id" and t.up in ("ON", "RETURNING"):
                    break
                elif depth >= 1 and _literal(t):
                    owner[sig[p]] = insert_cols[pos] if insert_cols and pos < len(insert_cols) else None
                elif depth >= 1 and t.kind == "id" and t.up == "SELECT":
                    # a subquery inside VALUES: nothing after this can be placed
                    return owner, True
                p += 1
        elif at(p) and at(p).up in ("SELECT", "WITH"):
            return owner, True  # INSERT ... SELECT: values come from elsewhere; every literal stays masked
    # assignments (UPDATE ... SET, ON CONFLICT DO UPDATE SET) and conditions (WHERE): the column is the name just
    # before an operator, until a separator.
    col, depth, last_id = None, 0, None
    while p < n:
        t = at(p)
        if t.text == "(":
            depth += 1
        elif t.text == ")":
            depth = max(0, depth - 1)
        if t.kind == "id" and t.up == "SELECT":
            return owner, True
        if t.kind in ("id", "qid") and t.up not in _COMPARE and t.up not in _RESET and t.up not in (
                "NULL", "EXCLUDED", "TRUE", "FALSE", "CASE", "WHEN", "THEN", "ELSE", "END", "CONFLICT", "UPDATE",
                "NOTHING", "ESCAPE", "COLLATE", "NOCASE"):
            nxt = at(p + 1)
            if nxt is not None and nxt.text == ".":
                pass  # table.column: the column comes next
            else:
                last_id = _name(t).lower()
        elif t.text in _COMPARE or t.up in _COMPARE:
            if last_id is not None:
                col = last_id
        elif (t.text == "," and depth == 0) or (t.kind == "id" and t.up in _RESET):
            col, last_id = None, None
        elif _literal(t):
            owner[sig[p]] = col
        p += 1
    return owner, False


def mask(sql, rules):
    """The statement with every value outside a loggable column replaced by ?."""
    toks = tokens(sql)
    verb, table, start = verb_and_table(toks)
    if verb is None:
        return None  # not a write
    if table is None:
        return f"-- {verb} (unreadable)"
    if table in rules.secret_tables:
        return f"-- {verb} {table} (hidden)"
    if table not in rules.columns:
        rules.undeclared.add((table, None))
        return f"-- {verb} {table} (columns not declared)"
    owner, opaque = place(toks, verb, table, start, rules)
    secret_row = False
    if table in rules.secret_rows:
        key_col, keys = rules.secret_rows[table]
        for i, c in owner.items():
            v = toks[i].text
            if c == key_col and v.startswith("'") and v[1:-1].replace("''", "'") in keys:
                secret_row = True
    out = []
    for i, t in enumerate(toks):
        if _literal(t):
            c = owner.get(i)
            keep = (not opaque and i in owner and rules.allowed(table, c)
                    and not (secret_row and c != rules.secret_rows[table][0])
                    and not any(s in t.text for s in rules.scrub))
            if c is not None and c not in rules.columns[table] and c not in rules.secret_columns.get(table, ()):
                rules.undeclared.add((table, c))
            out.append(t.text if keep else MASK)
        else:
            out.append(t.text)
    text = "".join(out)
    for s in rules.scrub:  # belt and braces: a secret inside an identifier or comment
        text = text.replace(s, "…")
    return text
