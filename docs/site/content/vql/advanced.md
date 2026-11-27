---
title: Advanced VQL
description: Lazy evaluation, stored queries with arguments, lambdas, lookups, parallel work and debugging in Atlantiraptor VQL.
---

## Lazy evaluation

VQL only computes what it has to. A column is computed when it is read:
if the `WHERE` rejects a row, columns the `WHERE` doesn't use are never
computed for it. A `LET x = SELECT …` runs only when `x` is read, and
`LIMIT` stops the plugin as soon as enough rows have passed.

This makes cheap-first queries fast, but it also means:

- an expensive function used in both a column and the `WHERE` runs for
  every row; filter on cheap columns first,
- a lazy `LET` read three times runs three times; use `<=` to run it once.

## Stored queries with arguments

A `LET` can take parameters, which turns it into a reusable function or
query:

```sql
LET Double(X) = X * 2

LET ProcessesNamed(N) = SELECT Pid, Name FROM pslist() WHERE Name =~ N

SELECT * FROM ProcessesNamed(N="ssh")
```

Arguments are named when called, like everywhere else in VQL.

## Lambdas

Some functions take a small function as a string, written `x=>…`:

```sql
SELECT filter(list=Hashes, condition="x=>x =~ '^e3b0'") AS EmptyFileHashes
FROM ...
```

Functions such as `filter()` take them; see each function's entry in the
[reference](/reference/vql/).

## Lookups with memoize

To join two sets of rows by key, load one into a lookup table once and
read it per row:

```sql
LET procs <= memoize(query={ SELECT Pid, Name FROM pslist() }, key="Pid")

SELECT Laddr, Raddr, Pid, get(item=procs, field=str(str=Pid)).Name AS Process
FROM netstat()
```

`cache()` remembers the result of an expression by key for a while, which
helps when the same value (a hash, a signature check) would be computed
many times.

## Flattening and dicts

- `flatten()` turns a row with a list column into one row per item.
- `items()` turns a dict into rows of `_key` and `_value`.
- `to_dict()` turns rows of `_key` and `_value` back into a dict.
- `dict()` builds one; `+` merges two.

## Doing work in parallel

`foreach()` takes `workers=N` to run its inner query on several rows at
once, which speeds up I/O-bound work (hashing, parsing many files):

```sql
SELECT * FROM foreach(
  row={ SELECT OSPath FROM glob(globs="/usr/bin/*") },
  query={ SELECT OSPath, hash(path=OSPath).SHA256 AS SHA256 FROM scope() },
  workers=4)
```

Rows then come back in no particular order. On endpoints, remember the
CPU limit: more workers is not always faster.

## Running a query as someone else

`query()` runs a query given as a string, and on the server can run it
with another user's permissions (`runas=`) if you have the
`IMPERSONATION` permission. This is how automation can act on a user's
behalf without more rights than needed.

## Debugging

- `log()` writes a message and returns TRUE: drop it into a `WHERE` to
  trace which rows are checked.
- On the command line, `-v` prints detailed logs, and `--trace_vql` traces
  every plugin call.
- In a collection, the **Log** tab shows each query's progress, and the
  collection's overview shows rows and time per source.
- Split a large query into `LET` steps and select from each in turn to see
  where rows disappear.

See [Debugging](/troubleshooting/debugging/) for profiling the client and
server.
