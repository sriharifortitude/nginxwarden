# 0001. Follow nginx's own inheritance rules

**Status:** accepted

## Decision

The rules ask "what is in effect here?" the way nginx answers it, not "is this
directive present somewhere?". For a directive in a block, the effective set of
a setting such as `add_header`, `proxy_ssl_verify`, `allow`/`deny` or
`server_tokens` is whatever the **nearest enclosing block that sets it at all**
defines. A block that sets one `add_header` replaces, rather than adds to, the
set it would have inherited.

## Reasoning

A search for `Strict-Transport-Security` in the file says the header is
present, and for the configuration in `testdata/vulnerable/` that is true: the
`server` block sets it. But the `location /assets/` inside that server adds a
`Cache-Control` header, and from that point nginx stops inheriting the server's
`add_header` lines. Responses under `/assets/` carry no HSTS and no
`X-Frame-Options`. Nothing warns about this, nothing fails, and a review of the
server block reads as secure. It is among the most common ways a hardened
configuration stops being one.

The same shape recurs. `proxy_ssl_verify on;` in the server block covers the
locations beneath it unless one sets its own; `allow`/`deny` in a parent
protects a `stub_status` below it. Rules that ignore inheritance either miss
the dropped header or flag the location that is in fact protected from above.

`Directive.effective(name)` is the one place that encodes the lookup; every
rule that needs it calls it.

## Costs

It models the inheritance of the directives it needs, not all of nginx. It does
not know about `map` and `geo` results, `if` semantics, or which directives
merge instead of replacing, so a rule on a directive outside its list says
nothing about it. A finding is evidence the configuration reads this way, not
a replay of a request.
