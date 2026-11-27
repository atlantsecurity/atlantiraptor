---
title: VQL fundamentals
description: Learn VQL step by step - SELECT, plugins and functions, WHERE, LET, types, operators, subqueries and aggregation - with examples you can run.
---

Every example on this page runs on your own machine with
`atlantiraptor query "<query>"`. Try them as you read.

## SELECT … FROM a plugin

```sql
SELECT * FROM info()
```

A query reads rows from a **plugin** (`info()`, `pslist()`, `glob()`,
`netstat()`…) and returns rows. `*` returns every column. To choose and
rename columns:

```sql
SELECT Name, Pid, Exe AS Path FROM pslist()
```

Plugins take named arguments:

```sql
SELECT OSPath, Size, Mtime
FROM glob(globs="/etc/*.conf")
```

Arguments are always named (`globs=`), never positional. The
[VQL reference](/reference/vql/) lists each plugin's arguments.

When a query has no natural source, select from `scope()`, which returns
one row:

```sql
SELECT now() AS Now, upcase(string="hello") AS Shout FROM scope()
```

## Functions

**Functions** return a value instead of rows, and are used in columns and
conditions:

```sql
SELECT OSPath, hash(path=OSPath).SHA256 AS SHA256
FROM glob(globs="/usr/bin/ss*")
```

`hash()` returns an object with `MD5`, `SHA1` and `SHA256` fields; the
`.` picks one. Plugins and functions sometimes share a name (`parse_csv()`
is both); VQL knows which one you mean from where you use it.

## WHERE

```sql
SELECT Name, Pid, CommandLine FROM pslist()
WHERE Name =~ "ssh" AND Pid > 1000
```

| Operator | Meaning |
|---|---|
| `=`, `!=`, `<`, `>`, `<=`, `>=` | Comparison |
| `=~` | Regular expression match, **case insensitive** |
| `AND`, `OR`, `NOT` | Logic (`&&` and `\|\|` also work) |
| `IN` | Membership in a list: `Name IN Names` |
| `+`, `-`, `*`, `/`, `%` | Arithmetic; `+` also joins strings and lists |

`=~` takes a Go regular expression, so `"^C:\\\\Windows"` matches a
literal backslash. Combine alternatives with `|`: `Name =~ "cmd|powershell"`.

## Values and types

| Type | Written as |
|---|---|
| String | `"double"` or `'single'` quotes, or `'''triple quotes'''` across lines |
| Number | `42`, `3.14`, `0x1f` |
| Boolean | `TRUE`, `FALSE` |
| Null | `NULL` |
| List | `("a", "b")` |
| Dict | `dict(Name="x", Size=1)` |

Lists are indexed from zero, and negative indexes count from the end:
`L[0]`, `L[-1]`. Strings can be sliced: `"abcdef"[1:3]`. Fields of a dict
or object are read with `.`: `hash(path=P).SHA256`, `Data.value`.

Missing values are `NULL`, and `NULL` is false, so `A || B` gives the first
of `A` and `B` that is set:

```sql
SELECT Username || "unknown" AS User FROM pslist()
```

Names with spaces or odd characters are written in backticks:
`` `Logon Type` ``.

## LET

`LET` names a value or a query for later use:

```sql
LET threshold = 100000000

LET big_files = SELECT OSPath, Size FROM glob(globs="/var/log/**")
  WHERE Size > threshold

SELECT * FROM big_files
```

A query can hold several statements. Only the last `SELECT` returns rows;
the `LET`s before it set things up.

There are two kinds of `LET` for queries:

- `LET x = SELECT …` is **lazy**: the query runs each time `x` is read.
- `LET x <= SELECT …` runs **once**, now, and keeps the rows in memory.

Use `<=` for small results you read several times (a lookup table), and
`=` for large results you read once.

A stored query read as a value gives its rows as a list, and a column of
it gives a list of values:

```sql
LET shells <= SELECT Name, Pid FROM pslist() WHERE Name =~ "sh$"
SELECT shells.Pid AS ShellPids, len(list=shells) AS Count FROM scope()
```

## Subqueries

Many plugins take a query as an argument, written in braces:

```sql
SELECT * FROM if(
  condition=TRUE,
  then={ SELECT "yes" AS Answer FROM scope() },
  else={ SELECT "no" AS Answer FROM scope() })
```

`foreach()` runs a query once for every row of another, with that row's
columns available inside:

```sql
SELECT * FROM foreach(
  row={ SELECT Pid AS ProcPid, Name AS ProcName FROM pslist()
        WHERE Name =~ "sshd" },
  query={ SELECT ProcName, Pid, Laddr, Raddr FROM netstat()
          WHERE Pid = ProcPid })
```

Inside the inner query, the inner plugin's own columns hide outer columns
of the same name. That's why the outer `Pid` is renamed to `ProcPid`: a
plain `WHERE Pid = Pid` would compare each connection's `Pid` with itself.

`chain()` runs several queries one after the other, and `switch()` returns
the first that produces rows.

## Sorting, limiting, grouping

```sql
SELECT Name, count() AS Count
FROM pslist()
GROUP BY Name
ORDER BY Count DESC
LIMIT 10
```

- `ORDER BY` takes one column name; add `DESC` to reverse.
- `LIMIT` stops after that many rows (and stops the query early, which is
  cheap).
- `GROUP BY` collapses rows with the same value into one. **Aggregate
  functions** compute over each group: `count()`, `sum()`, `min()`,
  `max()`, `enumerate()` (all values as a list).

## Comments

```sql
-- a comment to the end of the line
// also a comment
/* a comment
   over several lines */
```

## Errors and logs

A query that hits a problem usually logs it and carries on with the next
row, rather than stopping. Read the log: the collection's **Log** tab, a
notebook cell's messages, or the terminal for `atlantiraptor query`. Add
`-v` on the command line for detailed logs, and use `log()` to write your
own messages:

```sql
SELECT * FROM pslist()
WHERE log(message="Checking %v", args=Name) AND Name =~ "ssh"
```

`log()` returns TRUE, so it can sit in a `WHERE` without changing the
result.

## Next

- [Advanced VQL](/vql/advanced/): more about lazy evaluation, custom
  functions, materialising, performance.
- [Writing artifacts](/artifacts/writing/): put your query into an
  artifact others can run.
