---
title: VQL problems
description: Understand and fix common Atlantiraptor VQL errors and surprises - syntax errors, missing rows, NULLs, types, and slow queries.
---

## Syntax errors

VQL reports where it stopped parsing, with the text around it:

```text
Unable to parse VQL Query: SELECT x|=>x+1 AS L: 1:9: unexpected token "=>"
```

The `|` marks the position. Common causes:

- **Arguments without names.** `hash(OSPath)` must be `hash(path=OSPath)`.
- **Reserved words as names.** `AS`, `IN`, `OR`, `AND`, `NOT`, `LIMIT`
  and other keywords can't be column names (`AS As` fails). Pick another
  name or use backticks.
- **List literals in the wrong place.** `[1, 2]` works as a function
  argument; elsewhere write a list as `(1, 2)`.
- **`IN` with square brackets.** Write the list in parentheses:
  `Name IN ("cmd.exe", "powershell.exe")`.
- **Quotes inside quotes.** Mix `'` and `"`, or use `'''…'''` for long
  strings.
- **Lambdas outside functions that take them.** `x=>x+1` is a string
  argument to functions like `filter()`, not an expression on its own.

## The query runs but returns nothing

- Remove the `WHERE` and check that the plugin returns rows at all.
- **Regexes**: `=~` is case-insensitive and matches anywhere in the
  string; anchor with `^` and `$` when needed. Backslashes need escaping
  twice in strings: `"C:\\\\Windows"`.
- **Shadowed names**: in `foreach()` the inner plugin's columns hide outer
  columns with the same name, so `WHERE Pid = Pid` is always true. Rename
  outer columns.
- **Preconditions**: an artifact source whose precondition fails is
  skipped; the log says so.
- **Permissions**: functions that need a permission you don't have return
  nothing and log an error.

## Values are NULL

- A missing field reads as `NULL` rather than an error: check the spelling
  and case (`OSPath`, not `Ospath`).
- Functions log their errors and return `NULL`: look at the log for
  messages such as "hash: file not found".
- `parse_json()` and similar return `NULL` for invalid input.

Use `log()` or select intermediate columns to see what you actually have.

## Types

- Numbers from text are strings until converted: `int(int=X)`,
  `parse_float(string=X)`.
- Times compare as times only when both sides are times:
  `timestamp(string="2026-01-01")`, `timestamp(epoch=…)`.
- `bool` parameters arrive converted, but a value read from a file is a
  string; compare it explicitly.
- `typeof(x=Value)` tells you what a value is.

## Slow queries

- Filter early on cheap columns, before expensive functions; see
  [Tips](/artifacts/tips/).
- Use `LET … <=` for small results you read many times, `=` for large
  ones you read once.
- Narrow globs; avoid `C:/**` unless you need it.
- `-v` on the command line, or the collection log, shows the time each
  query took; `--trace_vql` shows every plugin call.

## Different results on different machines

Artifacts run on the endpoint, with its OS version, language, installed
software and permissions. Compare a working and a failing machine's
collection logs side by side, and check the agent versions.
