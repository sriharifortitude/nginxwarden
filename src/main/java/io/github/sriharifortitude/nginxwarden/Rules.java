package io.github.sriharifortitude.nginxwarden;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The checks. Each takes the root of a parsed configuration and returns findings. */
final class Rules {

	static final String META_ID = "NW000";
	static final String META_FIX = "Write `# nginxwarden:ignore NW001 -- why this is acceptable`.";

	/** Headers whose absence or loss matters; the inheritance and `always` rules look at these. */
	static final Set<String> SECURITY_HEADERS = Set.of(
			"strict-transport-security", "x-frame-options", "x-content-type-options",
			"content-security-policy", "referrer-policy", "permissions-policy");

	static final List<Rule> ALL = List.of(
			new Rule("NW001", "alias-off-by-slash", "alias path traversal (off-by-slash)", Severity.HIGH,
					"With `location /static { alias /app/static/; }` nginx replaces the matched prefix `/static` with the alias path, so a request for `/static../secrets` becomes `/app/static/../secrets` and escapes the directory. It happens whenever the location has no trailing slash and the alias does. The mismatch is easy to miss, because both lines look right on their own.",
					"Make the two agree: `location /static/ { alias /app/static/; }`.",
					Rules::aliasOffBySlash),
			new Rule("NW002", "add-header-inheritance", "add_header in a block drops the security headers set above it", Severity.MEDIUM,
					"nginx inherits add_header from the enclosing level only if the current level has no add_header of its own. A location that adds `Cache-Control` therefore silently stops sending the HSTS, X-Frame-Options and similar headers the server block set, with no warning.",
					"Repeat the security headers in the block that adds its own, or put them in an included snippet every block pulls in.",
					Rules::addHeaderInheritance),
			new Rule("NW003", "header-not-always", "security header not sent on error responses", Severity.LOW,
					"add_header only applies to successful and redirect responses (200, 201, 204, 206, 301, 302, 303, 304, 307, 308) unless the `always` parameter is given. A security header without it is missing from 4xx and 5xx pages.",
					"Add `always`: `add_header X-Frame-Options DENY always;`.",
					Rules::headerNotAlways),
			new Rule("NW004", "weak-tls", "obsolete TLS protocol or cipher enabled", Severity.HIGH,
					"SSLv2, SSLv3, TLS 1.0 and TLS 1.1 have known protocol weaknesses; the IETF has deprecated SSLv2 (RFC 6176), SSLv3 (RFC 7568) and TLS 1.0 and 1.1 (RFC 8996). Ciphers such as RC4, DES, 3DES, MD5, EXPORT and NULL are broken or have no encryption at all.",
					"`ssl_protocols TLSv1.2 TLSv1.3;` and a cipher list from a current profile (for example Mozilla's intermediate).",
					Rules::weakTls),
			new Rule("NW005", "server-tokens", "nginx version disclosed", Severity.LOW,
					"server_tokens defaults to `on`, which puts the exact nginx version in the Server header and on error pages. That tells a scanner which known vulnerabilities to try.",
					"`server_tokens off;` in the http block.",
					Rules::serverTokens),
			new Rule("NW006", "autoindex", "directory listing enabled", Severity.MEDIUM,
					"`autoindex on` lists every file in a directory that has no index file, including backups and files nobody meant to publish.",
					"Remove it, or restrict the location to the directories that should be browsable.",
					Rules::autoindex),
			new Rule("NW007", "no-hsts", "TLS server without Strict-Transport-Security", Severity.MEDIUM,
					"Without HSTS a browser that is sent to http:// once (a typed address, an old link) makes that request in the clear, which is the one a network attacker needs. A max-age under six months gives little protection.",
					"`add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;`",
					Rules::hsts),
			new Rule("NW008", "proxy-pass-variable-host", "proxy_pass target chosen by the client", Severity.HIGH,
					"If the host part of proxy_pass contains a request-controlled variable ($host, $http_*, $arg_*, $cookie_*), a client chooses where nginx connects. That is server-side request forgery against anything nginx can reach, including internal services and cloud metadata.",
					"Use a fixed host or an upstream block, and choose between backends with a `map` over a value you control.",
					Rules::proxyPassVariable),
			new Rule("NW009", "open-stub-status", "stub_status reachable without restriction", Severity.MEDIUM,
					"stub_status exposes connection counts and request totals. With no `allow`/`deny` and no authentication it is readable by anyone who can reach the location.",
					"`allow 127.0.0.1; deny all;` (or `auth_basic`) in the location.",
					Rules::stubStatus),
			new Rule("NW010", "unlimited-body", "request body size limit turned off", Severity.MEDIUM,
					"`client_max_body_size 0` removes the limit, so one client can stream an arbitrarily large body into the server's disk or memory.",
					"Set the largest body the application legitimately accepts, per location if it differs.",
					Rules::unlimitedBody),
			new Rule("NW011", "proxy-tls-unverified", "upstream TLS certificate not verified", Severity.MEDIUM,
					"proxy_ssl_verify is off by default. `proxy_pass https://...` therefore encrypts the connection and accepts any certificate, so an attacker on the path to the upstream can impersonate it.",
					"`proxy_ssl_verify on; proxy_ssl_trusted_certificate /path/ca.pem; proxy_ssl_server_name on;`",
					Rules::proxyTlsVerify),
			new Rule("NW012", "cors-reflects-origin", "CORS Allow-Origin reflects the request's Origin", Severity.HIGH,
					"`add_header Access-Control-Allow-Origin $http_origin` echoes back whatever Origin the browser sent, so every website is allowed. With `Access-Control-Allow-Credentials: true` any site can read authenticated responses on the visitor's behalf.",
					"Allow an explicit list with `map $http_origin $cors_origin { default \"\"; \"https://app.example.com\" $http_origin; }` and send $cors_origin.",
					Rules::corsReflect),
			new Rule("NW013", "root-is-system-dir", "document root is the filesystem root or a system directory", Severity.HIGH,
					"`root /;` (or /etc, /root, /home, /proc) makes every file nginx can read reachable by URL.",
					"Point root at the directory that holds only what should be public.",
					Rules::rootSystemDir),
			new Rule("NW014", "user-root", "worker processes run as root", Severity.MEDIUM,
					"`user root;` makes the worker processes, which parse untrusted requests, run as root. A memory-safety bug in nginx or a module then yields a root shell.",
					"Use an unprivileged account (`user www-data;` or `nginx`).",
					Rules::userRoot));

	private Rules() {
	}

	static Optional<Rule> byId(String id) {
		return ALL.stream().filter(r -> r.id().equals(id)).findFirst();
	}

	static List<Finding> run(Directive root) {
		List<Finding> out = new ArrayList<>();
		for (Rule r : ALL) {
			out.addAll(r.check().apply(root));
		}
		return out;
	}

	private static Finding at(String rule, Severity severity, Directive d, String message) {
		return new Finding(rule, severity, d.file, d.line, message);
	}

	private static void each(Directive root, Consumer<Directive> visitor) {
		root.walk(visitor);
	}

	private static String lower(String s) {
		return s.toLowerCase(Locale.ROOT);
	}

	// ---- NW001 -------------------------------------------------------------

	private static List<Finding> aliasOffBySlash(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (!d.name.equals("location") || !d.isBlock()) {
				return;
			}
			String modifier = d.args.size() > 1 ? d.arg(0) : "";
			String path = d.args.isEmpty() ? null : d.args.get(d.args.size() - 1).text();
			boolean prefix = modifier.isEmpty() || modifier.equals("^~");
			if (path == null || !prefix || path.endsWith("/")) {
				return;
			}
			for (Directive alias : d.childrenNamed("alias")) {
				String target = alias.arg(0);
				if (target != null && target.endsWith("/")) {
					out.add(at("NW001", Severity.HIGH, alias,
							"location " + path + " has no trailing slash but alias " + target + " does, so a request for " + path + "../ walks out of " + target));
				}
			}
		});
		return out;
	}

	// ---- NW002 / NW003 -----------------------------------------------------

	private static String headerName(Directive addHeader) {
		String n = addHeader.arg(0);
		return n == null ? "" : lower(n);
	}

	private static List<Finding> addHeaderInheritance(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, block -> {
			if (!block.isBlock() || block.name.isEmpty()) {
				return;
			}
			List<Directive> own = block.childrenNamed("add_header");
			if (own.isEmpty() || block.parent == null) {
				return;
			}
			List<Directive> inherited = block.parent.effective("add_header");
			Set<String> ownNames = new java.util.HashSet<>();
			own.forEach(h -> ownNames.add(headerName(h)));
			List<String> lost = new ArrayList<>();
			for (Directive h : inherited) {
				String n = headerName(h);
				if (SECURITY_HEADERS.contains(n) && !ownNames.contains(n) && !lost.contains(n)) {
					lost.add(n);
				}
			}
			if (!lost.isEmpty()) {
				out.add(at("NW002", Severity.MEDIUM, own.get(0),
						block.name + (block.args.isEmpty() ? "" : " " + block.arg(block.args.size() - 1)) + " has its own add_header, so it no longer inherits " + String.join(", ", lost)));
			}
		});
		return out;
	}

	private static List<Finding> headerNotAlways(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (d.name.equals("add_header") && SECURITY_HEADERS.contains(headerName(d))
					&& !(d.args.size() >= 3 && d.args.get(d.args.size() - 1).text().equals("always"))) {
				out.add(at("NW003", Severity.LOW, d, d.arg(0) + " is not sent on error responses without `always`"));
			}
		});
		return out;
	}

	// ---- NW004 -------------------------------------------------------------

	private static final Set<String> OBSOLETE_PROTOCOLS = Set.of("sslv2", "sslv3", "tlsv1", "tlsv1.1");
	private static final Set<String> WEAK_CIPHER_WORDS = Set.of("RC4", "DES", "3DES", "MD5", "NULL", "ANULL", "ENULL", "EXPORT", "EXP", "LOW");

	private static List<Finding> weakTls(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (d.name.equals("ssl_protocols")) {
				List<String> bad = d.args.stream().map(a -> lower(a.text())).filter(OBSOLETE_PROTOCOLS::contains).toList();
				if (!bad.isEmpty()) {
					out.add(at("NW004", Severity.HIGH, d, "ssl_protocols enables " + String.join(", ", bad)));
				}
			} else if (d.name.equals("ssl_ciphers") && d.arg(0) != null) {
				List<String> bad = new ArrayList<>();
				for (String c : d.arg(0).split(":")) {
					if (c.isEmpty() || c.startsWith("!") || c.startsWith("-") || c.startsWith("@")) {
						continue;
					}
					String word = c.startsWith("+") ? c.substring(1) : c;
					if (WEAK_CIPHER_WORDS.contains(word.toUpperCase(Locale.ROOT))) {
						bad.add(word);
					}
				}
				if (!bad.isEmpty()) {
					out.add(at("NW004", Severity.HIGH, d, "ssl_ciphers allows " + String.join(", ", bad)));
				}
			}
		});
		return out;
	}

	// ---- NW005 / NW006 -----------------------------------------------------

	private static List<Finding> serverTokens(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (d.name.equals("server_tokens") && d.hasArg("on")) {
				out.add(at("NW005", Severity.LOW, d, "server_tokens on puts the nginx version in every response"));
			}
			if (d.name.equals("http") && d.isBlock()) {
				boolean httpOff = d.childrenNamed("server_tokens").stream().anyMatch(t -> t.hasArg("off"));
				List<Directive> servers = d.childrenNamed("server");
				boolean everyServerOff = !servers.isEmpty() && servers.stream()
						.allMatch(s -> s.effective("server_tokens").stream().anyMatch(t -> t.hasArg("off")));
				boolean explicitOn = d.childrenNamed("server_tokens").stream().anyMatch(t -> t.hasArg("on"));
				if (!httpOff && !everyServerOff && !explicitOn) {
					out.add(at("NW005", Severity.LOW, d, "no server_tokens off in http, so the default (on) sends the nginx version"));
				}
			}
		});
		return out;
	}

	private static List<Finding> autoindex(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (d.name.equals("autoindex") && d.hasArg("on")) {
				out.add(at("NW006", Severity.MEDIUM, d, "autoindex on lists the files in any directory without an index"));
			}
		});
		return out;
	}

	// ---- NW007 -------------------------------------------------------------

	private static final Pattern MAX_AGE = Pattern.compile("max-age\\s*=\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
	private static final long SIX_MONTHS = 15_552_000L;

	private static boolean servesTls(Directive server) {
		for (Directive l : server.childrenNamed("listen")) {
			if (l.hasArg("ssl") || l.hasArg("quic")) {
				return true;
			}
		}
		return server.childrenNamed("ssl").stream().anyMatch(s -> s.hasArg("on"));
	}

	private static List<Finding> hsts(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, server -> {
			if (!server.name.equals("server") || !server.isBlock() || !servesTls(server)) {
				return;
			}
			Directive hsts = null;
			for (Directive h : server.effective("add_header")) {
				if (headerName(h).equals("strict-transport-security")) {
					hsts = h;
				}
			}
			if (hsts == null) {
				out.add(at("NW007", Severity.MEDIUM, server, "this TLS server sends no Strict-Transport-Security header"));
				return;
			}
			Matcher m = hsts.arg(1) == null ? null : MAX_AGE.matcher(hsts.arg(1));
			if (m != null && m.find() && Long.parseLong(m.group(1)) < SIX_MONTHS) {
				out.add(at("NW007", Severity.LOW, hsts, "Strict-Transport-Security max-age=" + m.group(1) + " is under six months (15552000)"));
			}
		});
		return out;
	}

	// ---- NW008 / NW011 -----------------------------------------------------

	private static final Pattern CLIENT_VARIABLE = Pattern.compile(
			"\\$\\{?(arg_\\w+|http_\\w+|cookie_\\w+|host|args|query_string)\\}?");

	/** These values start with a slash, so they end the host part of a proxy_pass target rather than choosing it. */
	private static final Pattern PATH_VARIABLE = Pattern.compile("\\$\\{?(uri|request_uri|document_uri)\\}?");

	private static List<Finding> proxyPassVariable(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (!d.name.equals("proxy_pass") || d.arg(0) == null) {
				return;
			}
			String target = d.arg(0);
			int scheme = target.indexOf("://");
			String rest = scheme >= 0 ? target.substring(scheme + 3) : target;
			int slash = rest.indexOf('/');
			String authority = slash >= 0 ? rest.substring(0, slash) : rest;
			// A variable as the whole target ($scheme://$host...) has its authority in the variable text.
			if (scheme < 0 && target.startsWith("$")) {
				authority = target;
			}
			Matcher cut = PATH_VARIABLE.matcher(authority);
			if (cut.find()) {
				authority = authority.substring(0, cut.start());
			}
			Matcher m = CLIENT_VARIABLE.matcher(authority);
			if (m.find()) {
				out.add(at("NW008", Severity.HIGH, d, "proxy_pass " + target + " takes its host from $" + m.group(1).replace("{", "") + ", which the client controls"));
			}
		});
		return out;
	}

	private static List<Finding> proxyTlsVerify(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (!d.name.equals("proxy_pass") || d.arg(0) == null || !lower(d.arg(0)).startsWith("https://")) {
				return;
			}
			boolean verified = d.effective("proxy_ssl_verify").stream().anyMatch(v -> v.hasArg("on"));
			if (!verified) {
				out.add(at("NW011", Severity.MEDIUM, d, "proxy_pass " + d.arg(0) + " uses TLS but proxy_ssl_verify is not on, so any certificate is accepted"));
			}
		});
		return out;
	}

	// ---- NW009 / NW010 -----------------------------------------------------

	private static List<Finding> stubStatus(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (!d.name.equals("stub_status")) {
				return;
			}
			boolean restricted = !d.effective("deny").isEmpty()
					|| d.effective("auth_basic").stream().anyMatch(a -> !a.hasArg("off"))
					|| !d.effective("auth_request").isEmpty();
			if (!restricted) {
				out.add(at("NW009", Severity.MEDIUM, d, "stub_status has no allow/deny or authentication in effect"));
			}
		});
		return out;
	}

	private static List<Finding> unlimitedBody(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (d.name.equals("client_max_body_size") && d.arg(0) != null && d.arg(0).matches("0[kKmMgG]?")) {
				out.add(at("NW010", Severity.MEDIUM, d, "client_max_body_size " + d.arg(0) + " removes the request body limit"));
			}
		});
		return out;
	}

	// ---- NW012 -------------------------------------------------------------

	private static List<Finding> corsReflect(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (!d.name.equals("add_header") || !"access-control-allow-origin".equals(headerName(d)) || d.arg(1) == null) {
				return;
			}
			if (!d.arg(1).matches("\\$\\{?http_origin\\}?")) {
				return;
			}
			boolean credentials = d.parent != null && d.parent.effective("add_header").stream()
					.anyMatch(h -> "access-control-allow-credentials".equals(headerName(h)) && h.hasArg("true"));
			out.add(at("NW012", credentials ? Severity.CRITICAL : Severity.HIGH, d,
					"Access-Control-Allow-Origin echoes $http_origin, so every origin is allowed" + (credentials ? ", and credentials are allowed too" : "")));
		});
		return out;
	}

	// ---- NW013 / NW014 -----------------------------------------------------

	private static final Set<String> SYSTEM_DIRS = Set.of("/", "/etc", "/root", "/home", "/proc", "/var");

	private static List<Finding> rootSystemDir(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (d.name.equals("root") && d.arg(0) != null) {
				String path = d.arg(0).length() > 1 ? d.arg(0).replaceAll("/+$", "") : d.arg(0);
				if (SYSTEM_DIRS.contains(path)) {
					out.add(at("NW013", Severity.HIGH, d, "root " + d.arg(0) + " serves a system directory"));
				}
			}
		});
		return out;
	}

	private static List<Finding> userRoot(Directive root) {
		List<Finding> out = new ArrayList<>();
		each(root, d -> {
			if (d.name.equals("user") && !d.isBlock() && "root".equals(d.arg(0))) {
				out.add(at("NW014", Severity.MEDIUM, d, "the worker processes run as root"));
			}
		});
		return out;
	}
}
