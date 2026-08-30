# TODO

Known technical debt, roughly in the order it is worth paying down. Most of
this came out of the 1.9.5–1.9.7 security work, where the same class of bug had
to be fixed three times in three different places.

## Rewrite the SQLBox backends on prepared statements

This is the big one. `addons/sqlbox/gw/sqlbox_{mysql,pgsql,sqlite3,mssql}.c`
all build SQL by pasting escaped values into a format string:

```c
sql = octstr_format(SQLBOX_MYSQL_INSERT_QUERY, sqlbox_logtable,
                    st_str(momt), st_str(msg->sms.sender), ...);
```

Every injection fixed in 1.9.5, 1.9.6 and 1.9.7 was a bug in *how a value was
quoted*, and each backend had to be reasoned about separately — MySQL needs
character-set-aware escaping, PostgreSQL depends on `standard_conforming_strings`,
SQLite and SQL Server need neither. That reasoning has to be redone by every
future reader, and getting it wrong is silent.

`sqlbox_oracle.c` already does the right thing: it binds values as parameters
and its `get_string_value_or_return_null()` does no quoting at all, because
there is nothing to quote. It was the one backend never affected by any of the
three bugs. The other four should look like it.

Concretely:

- MySQL: `mysql_stmt_prepare` / `mysql_stmt_bind_param` / `mysql_stmt_execute`.
- PostgreSQL: `PQexecParams` (or `PQprepare` + `PQexecPrepared`) with `$1..$n`.
  This also removes the multi-statement exposure — `PQexecParams` runs exactly
  one statement, unlike `PQexec`.
- SQLite: `sqlite3_prepare_v2` / `sqlite3_bind_*` / `sqlite3_step`.
- SQL Server: `SQLPrepare` / `SQLBindParameter`, or the FreeTDS equivalent.

The INSERT column list is 27 values and identical across backends, so most of
this is one shared shape repeated four times. `gwlib/dbpool.h` already carries
a binding abstraction (`dbpool_conn_update` takes a `List *binds`, which is how
Oracle works today) — extending that to the other drivers is probably the
cleanest route, and would let SQLBox stop caring which backend it is on.

Once this lands, `get_string_value_or_return_null()` and the `st_str`/`st_num`
macros can go away entirely in all four files.

## Smaller items in the same area

- **`sqlbox_mysql.c` interpolates `foreign_id` and `id` unescaped** into
  `DELETE ... WHERE sql_id in (%S)` (`mysql_save_list`) and
  `DELETE ... WHERE sql_id = %S` (`mysql_fetch_msg`). Not exploitable today —
  those values are the server's own `BIGINT` primary key, read straight back
  out of the insert table — but `foreign_id` is an ordinary message field that
  *is* attacker-influenced on the `mysql_save_msg` path. Only the call graph
  makes it safe. Bind it, or at minimum check it is all digits.

- **The connection character set is never pinned.** `gwlib/dbpool_mysql.c`
  (`mysql_open_conn`) never calls
  `mysql_options(mysql, MYSQL_SET_CHARSET_NAME, ...)`, so the connection
  charset is whatever the server or `my.cnf` hands out. That is exactly how a
  deployment ends up on GBK or CP932 without anyone deciding to — which was the
  precondition for the 1.9.7 MySQL injection. A `charset =` directive in the
  config would make the choice deliberate. (The current escaping is correct
  either way, since it reads the charset off the connection.)

- **`max-connections` defaults to 1** in every SQLBox backend, and
  `dbpool_conn_consume()` blocks forever on an exhausted pool rather than
  returning `NULL` or timing out. That combination turns any accidental
  double-consume into a permanent silent hang with no log line. The 1.9.7
  restructure works within it, but the default deserves raising and the
  blocking behaviour deserves a timeout.

- **`dbpool_conn_consume()` can NULL-deref during shutdown.**
  `gwlib/dbpool.c` ends with `return (pc->conn != NULL ? pc : NULL)`, which
  dereferences `pc` unconditionally — but `gwlist_consume()` returns `NULL`
  once the pool's producer is removed in `dbpool_destroy()`. Pre-existing and
  unrelated to any of the above; worth its own fix.

## `exec` sms-services

- **`popen()` means there is always a shell.** `gw/smsbox.c` builds a command
  line and hands it to `popen()`, so every value has to be escaped for shell
  syntax, and 1.9.7 had to make that escaping track the quoting of the
  operator's own pattern. Splitting the pattern into an argv at config time and
  using `fork()` + `execvp()` would make injection structurally impossible
  instead of a property of the escaper. The catch is that it drops support for
  patterns using pipes, redirection or `&&`, so it needs to be opt-in (a new
  `exec-argv =` alongside `exec =`) rather than a change to existing behaviour.

- **A pattern that re-parses its command line cannot be made safe.**
  `sh -c "... %A ..."` and `eval` give the message body a second round of shell
  parsing, which undoes any escaping. 1.9.7 warns about this at start-up;
  an `exec-argv` form would be the actual answer.

- **`octstr_shell_escape()` is not NUL-safe.** An 8-bit MO message containing a
  NUL byte truncates `octstr_get_cstr(pattern)` at `popen()` mid-literal,
  producing a shell syntax error. Not injectable — truncation always lands
  inside the opening quote — but it is a cheap way to make an `exec` service
  fail, and the message is silently lost.

- **`exec` is undocumented.** There is no mention of it anywhere in `doc/`, and
  no sample config uses it, yet it is the feature behind two of the three
  security fixes. It needs a section covering at minimum: which escape codes
  carry attacker-controlled data, that values are quoted by Kannel so patterns
  should not quote them again, and that nesting a shell defeats the escaping.

## Test coverage

`checks/check_urltrans` (added in 1.9.7) is the only regression test any of
this work produced. Still missing:

- SQLBox value quoting, per backend. Hard to test without a live server, but
  the escaping helpers could be split into a pure function and tested directly,
  and the DB-backed part could run under the existing `checks/*.sh` pattern
  when a server is configured.
- `gwlib/octstr.c`'s `octstr_shell_escape()` has no unit test at all.
- Nothing exercises the DLR path through `urltrans_get_pattern()`, where the
  1.9.7 URL-encoding regression lived.
