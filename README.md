# nginxwarden

[![CI](https://github.com/sriharifortitude/nginxwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/nginxwarden/actions/workflows/ci.yml)

A security linter for nginx configuration. It follows `include`, applies nginx's
own inheritance rules, and reports the mistakes that read as correct in a
review: an `alias` that walks out of its directory, a location that silently
drops the security headers set above it, an `Access-Control-Allow-Origin` that
echoes any origin. Java 21, no runtime dependencies, MIT.

## Why

nginx configuration is short and forgiving, and several of its defaults and
rules fail silently:

- `add_header` is inherited from the enclosing block **only if the current block
  has none of its own**. Add a `Cache-Control` header to one location and that
  location stops sending HSTS and `X-Frame-Options`, with no warning.
- `location /static { alias /app/static/; }` lets `/static../` escape the
  directory, because the matched prefix is replaced by the alias path. Both lines
  look right alone.
- `proxy_pass https://...` does not verify the upstream's certificate unless
  `proxy_ssl_verify on` is set; the default is off.
- `server_tokens` defaults to on, and `stub_status` has no access control of its own.

None of these makes `nginx -t` fail. nginxwarden reads the files and reports
them with the line and the fix.

## What it finds

A configuration in `testdata/vulnerable/` with one included file
(`conf.d/admin.conf`):

<!-- demo:start -->
```
testdata/vulnerable/conf.d/admin.conf:1  MEDIUM   NW007  this TLS server sends no Strict-Transport-Security header
testdata/vulnerable/nginx.conf:1  MEDIUM   NW014  the worker processes run as root
testdata/vulnerable/nginx.conf:8  LOW      NW005  no server_tokens off in http, so the default (on) sends the nginx version
testdata/vulnerable/nginx.conf:12  MEDIUM   NW010  client_max_body_size 0 removes the request body limit
testdata/vulnerable/nginx.conf:18  HIGH     NW004  ssl_protocols enables tlsv1, tlsv1.1
testdata/vulnerable/nginx.conf:19  HIGH     NW004  ssl_ciphers allows RC4
testdata/vulnerable/nginx.conf:21  LOW      NW003  X-Frame-Options is not sent on error responses without `always`
testdata/vulnerable/nginx.conf:25  HIGH     NW001  location /static has no trailing slash but alias /srv/app/static/ does, so a request for /static../ walks out of /srv/app/static/
testdata/vulnerable/nginx.conf:29  MEDIUM   NW002  location /assets/ has its own add_header, so it no longer inherits x-frame-options, strict-transport-security
testdata/vulnerable/nginx.conf:30  MEDIUM   NW006  autoindex on lists the files in any directory without an index
testdata/vulnerable/nginx.conf:34  MEDIUM   NW011  proxy_pass https://backend.internal uses TLS but proxy_ssl_verify is not on, so any certificate is accepted
testdata/vulnerable/nginx.conf:35  MEDIUM   NW002  location /api/ has its own add_header, so it no longer inherits x-frame-options, strict-transport-security
testdata/vulnerable/nginx.conf:35  CRITICAL NW012  Access-Control-Allow-Origin echoes $http_origin, so every origin is allowed, and credentials are allowed too
testdata/vulnerable/nginx.conf:40  HIGH     NW008  proxy_pass http://$arg_target takes its host from $arg_target, which the client controls
testdata/vulnerable/nginx.conf:44  MEDIUM   NW009  stub_status has no allow/deny or authentication in effect
testdata/vulnerable/nginx.conf:50  HIGH     NW013  root / serves a system directory

16 finding(s): 1 critical, 5 high, 8 medium, 2 low, in 1 configuration(s)
```
<!-- demo:end -->

| Rule | Severity | What |
| --- | --- | --- |
| NW001 | high | `alias` path traversal (location without a trailing slash, alias with one) |
| NW002 | medium | a block's own `add_header` drops the security headers inherited from above |
| NW003 | low | security header without `always`, so missing from 4xx/5xx |
| NW004 | high | SSLv3, TLS 1.0/1.1, or RC4/DES/3DES/MD5/EXPORT/NULL ciphers |
| NW005 | low | `server_tokens` left on |
| NW006 | medium | `autoindex on` |
| NW007 | medium, low | TLS server with no HSTS, or `max-age` under six months |
| NW008 | high | `proxy_pass` whose host comes from the client (`$host`, `$arg_*`, ...) |
| NW009 | medium | `stub_status` with no `allow`/`deny` or authentication |
| NW010 | medium | `client_max_body_size 0` |
| NW011 | medium | `proxy_pass https://` without `proxy_ssl_verify on` |
| NW012 | high, critical | CORS `Allow-Origin` reflects `$http_origin` (critical with credentials) |
| NW013 | high | `root /` or another system directory |
| NW014 | medium | `user root;` |

`nginxwarden rules` prints each with why it matters and how to fix it.

The finding worth reading twice is NW002. In the demo, the `/assets/` location
adds a `Cache-Control` header, and from that line on it no longer inherits the
`X-Frame-Options` and `Strict-Transport-Security` the `server` block sets.
Responses under `/assets/` carry neither. A search for "Strict-Transport-Security"
in the file finds it; only following nginx's inheritance finds the gap
([ADR 1](docs/adr/0001-follow-nginxs-inheritance-rules.md)).

## Usage

```bash
git clone https://github.com/sriharifortitude/nginxwarden && cd nginxwarden
./gradlew jar                                   # build/libs/nginxwarden.jar, no dependencies

java -jar build/libs/nginxwarden.jar scan /etc/nginx          # a directory: its nginx.conf, else *.conf
java -jar build/libs/nginxwarden.jar scan --brief nginx.conf
java -jar build/libs/nginxwarden.jar scan --fail-on medium .
java -jar build/libs/nginxwarden.jar scan --format sarif . > nginxwarden.sarif
java -jar build/libs/nginxwarden.jar scan --prefix /etc/nginx site.conf
```

`include` is followed, with globs, and spliced in place so a snippet is judged
in the context that includes it. An include that matches no file (`mime.types`,
when scanning a copy away from `/etc/nginx`) is a note on stderr, not an error
([ADR 2](docs/adr/0002-includes-are-spliced-in-place.md)). `--prefix` says where
relative includes live.

Exit codes: 0 nothing at or above `--fail-on` (default `high`), 1 at least one
finding is, 2 a usage error or a file that could not be read. A configuration
with a syntax error fails the run even when everything else is clean, because a
check that exits 0 having read nothing looks like a result.

Suppress a finding with a reason, on its line or the line above:

```nginx
proxy_pass https://127.0.0.1:8443;  # nginxwarden:ignore NW011 -- loopback, same host
```

A suppression without a reason suppresses nothing and is itself reported (NW000).

## Run on real configurations

69 `.conf` files from three public repositories (h5bp's `server-configs-nginx`,
nginx's own `conf/`, and the nginx-admins-handbook), each scanned as its own
root so every fragment is parsed: 68 parsed. The one refusal,
`ngx_installer.conf`, is a shell script with a `.conf` extension, so refusing it
is correct. 12 findings: 6 NW007 (h5bp's example and test virtual hosts, which
do not set HSTS), 4 NW003 (two header lines without `always` in the handbook's
server templates) and 2 NW005 (`server_tokens` left at its default in nginx's
shipped file and the handbook's).

That is a small set of findings on purpose: those are hardened, widely copied
configurations. It shows the parser copes with real files and that the rules do
not cry wolf on them. It does not show the rules catch what they should. That
evidence is the fixtures and the tests, and I have not compared the output with
another tool.

Running it also found two defects in the first version, now fixed with tests:
an absolute Windows-style include path (`C:/...`) was not treated as absolute, and
`proxy_pass http://backend$request_uri;` was wrongly reported as a client-chosen
host (`$request_uri` starts with a slash, so it ends the host part).

## Tested

```bash
./gradlew build   # 54 tests; compiles with -Xlint:all -Werror
```

The lexer and parser have tests for quoting, `${var}`, comments, Lua blocks,
every syntax error with its line, nesting limits, include globbing, cycles,
unresolvable and illegal-in-a-path includes, UTF-8 and BOM handling. Each rule has
cases that must fire and cases that must not, including inheritance across
levels. Fifteen of the tests were run against deliberately broken copies of the
code to check they fail: variable parsing, quote escapes, cycle detection, the
alias slash condition, `add_header` inheritance, `always`, the HSTS threshold, the
`$request_uri` exemption, `proxy_ssl_verify` inheritance, `stub_status` access
control, the reason requirement, the size cap, the exit code for an unreadable
file, the inheritance walk and Windows drive paths. One survived at first (a client variable written after a path variable) and now has a test.
CI builds on Linux with Java 21 and diffs the example above against the jar's
real output.

**Not tested:** against a running nginx. I have not started a server and sent
`GET /static../secret` to confirm a traversal, and `nginx -t` was not run on the
fixtures. The behaviours the rules encode (`add_header` inheritance, the alias
replacement, `proxy_ssl_verify`'s default) come from the nginx documentation and
published write-ups of the alias issue, not from my own reproduction.

## Not covered

- OpenResty's Lua: `*_by_lua_block` bodies are skipped, not analysed.
- `map`, `geo`, `if` and `set` are parsed but not evaluated, so a value a variable
  holds is not known (NW008 judges the names it can see).
- Only the directives the rules mention have their inheritance modelled
  ([ADR 1](docs/adr/0001-follow-nginxs-inheritance-rules.md)).
- Templated configurations (Go templates, Jinja, envsubst) are not valid nginx and
  fail to parse.
- Anything outside the file: certificates, what the upstream does, file
  permissions, the operating system, a WAF in front.
- A config over 8 MiB is refused; so is invalid UTF-8.

See [`docs/adr/`](docs/adr/) for the decisions behind it.

## Licence

MIT.
