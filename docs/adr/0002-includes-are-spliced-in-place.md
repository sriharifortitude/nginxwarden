# 0002. Includes are spliced in place, and a missing one is a note

**Status:** accepted

## Decision

An `include` is replaced by the directives of the files it names, at that point
in the enclosing block, so a snippet is judged in the context that includes it.
Patterns with `*`, `?` and `[...]` in any path component are expanded and read in
sorted order. Relative paths are resolved against the configuration's directory
(or `--prefix`), then against the including file's directory.

An include that matches no file is a **note** on stderr, not an error, and
does not change the exit code. A file that exists but cannot be parsed, an
include cycle, or an include nested more than 16 deep is an error and makes
the exit code 2.

## Reasoning

nginx configurations are written to be read in place. `include
snippets/security-headers.conf;` is the whole point of a snippet, and the same
snippet is safe under one `server` and unsafe under another because of what
that server already defines (ADR 1). Judging the snippet alone would be
meaningless.

A missing include is common and not a defect in the scan. Configurations are
usually checked out away from `/etc/nginx`, so `include /etc/nginx/mime.types;`
and `include /etc/nginx/conf.d/*.conf;` point at files that are not there. Failing
the run for each would make the tool unusable on a repository; ignoring them
silently would hide that part of the configuration was not read. The note says
what was skipped.

Include patterns come from a file we do not trust. They are taken apart
component by component and never passed to the path API whole, because a
pattern such as `conf.d/*.conf` is not a legal path on Windows and `a<b>.conf`
is not legal anywhere. A component that is not a valid name matches nothing.

## Costs

A wrong guess about where an include resolves produces a note and a smaller
scan, not a crash. The note is on stderr, so a CI log shows it, but the exit
code does not: a scan that skipped half the configuration can still pass. Use
`--prefix` to point at the real layout.
