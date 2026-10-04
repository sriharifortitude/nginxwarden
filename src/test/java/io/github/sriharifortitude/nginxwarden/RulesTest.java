package io.github.sriharifortitude.nginxwarden;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RulesTest {

	@TempDir
	Path dir;

	/** Parse a configuration and return "RULE:line" for the findings of one rule. */
	private List<String> only(String rule, String conf) throws IOException {
		Path file = dir.resolve("nginx.conf");
		Files.writeString(file, conf);
		Directive root = new Parser(dir).parseFile(file);
		return Rules.run(root).stream().filter(f -> f.rule().equals(rule)).sorted(Finding.ORDER)
				.map(f -> f.rule() + ":" + f.line()).collect(Collectors.toList());
	}

	private static String http(String body) {
		return "http {\n" + body + "\n}\n";
	}

	private static String server(String body) {
		return http("server {\n" + body + "\n}");
	}

	// ---- NW001 -------------------------------------------------------------

	@Test
	void aliasOffBySlash() throws IOException {
		assertEquals(List.of("NW001:5"), only("NW001", server("location /static {\n  # x\n  alias /app/static/;\n}")));
		assertEquals(List.of("NW001:5"), only("NW001", server("location ^~ /img {\n  # x\n  alias /data/;\n}")));
		assertEquals(List.of(), only("NW001", server("location /static/ {\n  alias /app/static/;\n}")));
		assertEquals(List.of(), only("NW001", server("location /static {\n  alias /app/static;\n}")), "neither ends in a slash");
		assertEquals(List.of(), only("NW001", server("location = /f {\n  alias /app/f/;\n}")), "an exact match cannot be traversed");
		assertEquals(List.of(), only("NW001", server("location ~ ^/img/(.*)$ {\n  alias /data/$1;\n}")));
		assertEquals(List.of(), only("NW001", server("location /x {\n  root /srv/;\n}")));
	}

	// ---- NW002 / NW003 -----------------------------------------------------

	@Test
	void addHeaderInheritance() throws IOException {
		String base = "add_header X-Frame-Options DENY always;\nadd_header Strict-Transport-Security \"max-age=63072000\" always;\n";
		// server sets two security headers; the location adds Cache-Control and loses both.
		assertEquals(List.of("NW002:6"), only("NW002", server(base + "location /a {\n  add_header Cache-Control public;\n}")));
		// Repeating them keeps them.
		assertEquals(List.of(), only("NW002", server(base + "location /a {\n  add_header Cache-Control public;\n  add_header X-Frame-Options DENY always;\n  add_header Strict-Transport-Security \"max-age=63072000\" always;\n}")));
		// Losing only one still counts.
		assertEquals(List.of("NW002:6"), only("NW002", server(base + "location /a {\n  add_header Cache-Control public;\n  add_header X-Frame-Options DENY always;\n}")));
		// A header that is not a security header is not reported.
		assertEquals(List.of(), only("NW002", server("add_header X-Powered-By x;\nlocation /a {\n  add_header Cache-Control public;\n}")));
		// No add_header in the block: it inherits everything.
		assertEquals(List.of(), only("NW002", server(base + "location /a {\n  return 200;\n}")));
		// Inheritance skips a level that sets none: http sets, server sets none, location sets its own.
		assertEquals(List.of("NW002:5"), only("NW002", "http {\nadd_header X-Frame-Options DENY always;\nserver {\nlocation /a {\n  add_header Cache-Control public;\n}\n}\n}\n"));
	}

	@Test
	void headerNamesAreCaseInsensitive() throws IOException {
		assertEquals(List.of("NW002:5"), only("NW002", server("add_header x-frame-options DENY always;\nlocation /a {\n  add_header Cache-Control public;\n}")));
	}

	@Test
	void securityHeadersNeedAlways() throws IOException {
		assertEquals(List.of("NW003:3"), only("NW003", server("add_header X-Frame-Options DENY;")));
		assertEquals(List.of(), only("NW003", server("add_header X-Frame-Options DENY always;")));
		assertEquals(List.of(), only("NW003", server("add_header Cache-Control no-store;")));
		assertEquals(List.of("NW003:3"), only("NW003", server("add_header Strict-Transport-Security \"max-age=1\";")));
		assertEquals(List.of(), only("NW003", server("add_header Content-Security-Policy \"default-src 'self'\" always;")));
	}

	// ---- NW004 -------------------------------------------------------------

	@Test
	void obsoleteTlsProtocolsAndCiphers() throws IOException {
		assertEquals(List.of("NW004:3"), only("NW004", server("ssl_protocols TLSv1 TLSv1.2;")));
		assertEquals(List.of("NW004:3"), only("NW004", server("ssl_protocols SSLv3;")));
		assertEquals(List.of("NW004:3"), only("NW004", server("ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;")));
		assertEquals(List.of(), only("NW004", server("ssl_protocols TLSv1.2 TLSv1.3;")));
		assertEquals(List.of("NW004:3"), only("NW004", server("ssl_ciphers HIGH:RC4:!aNULL;")));
		assertEquals(List.of("NW004:3"), only("NW004", server("ssl_ciphers ALL:3DES;")));
		assertEquals(List.of(), only("NW004", server("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:!RC4:!MD5:!aNULL:-DES;")), "excluded ciphers are fine");
		assertEquals(List.of("NW004:3"), only("NW004", server("ssl_ciphers 'EXPORT:HIGH';")));
	}

	// ---- NW005 / NW006 -----------------------------------------------------

	@Test
	void serverTokens() throws IOException {
		assertEquals(List.of("NW005:1"), only("NW005", http("server { listen 80; }")));
		assertEquals(List.of(), only("NW005", http("server_tokens off;\nserver { listen 80; }")));
		assertEquals(List.of(), only("NW005", http("server { server_tokens off; }\nserver { server_tokens off; }")), "every server turns it off");
		assertEquals(List.of("NW005:1"), only("NW005", http("server { server_tokens off; }\nserver { listen 81; }")));
		assertEquals(List.of("NW005:2"), only("NW005", http("server_tokens on;\nserver { listen 80; }")), "explicit on is reported where it is written");
		assertEquals(List.of(), only("NW005", "server { listen 80; }\n"), "a fragment with no http block says nothing");
	}

	@Test
	void autoindex() throws IOException {
		assertEquals(List.of("NW006:3"), only("NW006", server("autoindex on;")));
		assertEquals(List.of(), only("NW006", server("autoindex off;")));
	}

	// ---- NW007 -------------------------------------------------------------

	@Test
	void hsts() throws IOException {
		assertEquals(List.of("NW007:2"), only("NW007", server("listen 443 ssl;")));
		assertEquals(List.of(), only("NW007", server("listen 80;")), "a plain-HTTP server has nothing to protect with HSTS");
		assertEquals(List.of(), only("NW007", server("listen 443 ssl;\nadd_header Strict-Transport-Security \"max-age=31536000\" always;")));
		assertEquals(List.of(), only("NW007", "http {\nadd_header Strict-Transport-Security \"max-age=31536000\" always;\nserver {\nlisten 443 ssl http2;\n}\n}\n"), "inherited from http");
		assertEquals(List.of("NW007:4"), only("NW007", server("listen 443 ssl;\nadd_header Strict-Transport-Security \"max-age=3600\" always;")), "reported on the header");
		assertEquals(List.of("NW007:2"), only("NW007", server("listen [::]:443 quic reuseport;")));
		assertEquals(List.of("NW007:2"), only("NW007", server("ssl on;")));
	}

	// ---- NW008 / NW011 -----------------------------------------------------

	@Test
	void proxyPassVariableHost() throws IOException {
		assertEquals(List.of("NW008:3"), only("NW008", server("proxy_pass http://$arg_target;")));
		assertEquals(List.of("NW008:3"), only("NW008", server("proxy_pass $scheme://$host$request_uri;")));
		assertEquals(List.of("NW008:3"), only("NW008", server("proxy_pass http://${http_x_backend}:8080;")));
		assertEquals(List.of("NW008:3"), only("NW008", server("proxy_pass http://$host.internal/;")));
		assertEquals(List.of(), only("NW008", server("proxy_pass http://backend$request_uri;")), "a variable in the path only");
		assertEquals(List.of(), only("NW008", server("proxy_pass http://backend/$arg_page;")));
		assertEquals(List.of(), only("NW008", server("proxy_pass http://$upstream_choice;")), "a variable the config itself sets");
		assertEquals(List.of(), only("NW008", server("proxy_pass http://backend:8080;")));
		assertEquals(List.of(), only("NW008", server("proxy_pass http://backend$uri$arg_page;")), "everything after a path variable is path");
		assertEquals(List.of("NW008:3"), only("NW008", server("proxy_pass http://$arg_h$uri;")), "a client variable before it still counts");
	}

	@Test
	void proxyTlsVerification() throws IOException {
		assertEquals(List.of("NW011:3"), only("NW011", server("proxy_pass https://api.internal;")));
		assertEquals(List.of(), only("NW011", server("proxy_pass https://api.internal;\nproxy_ssl_verify on;")));
		assertEquals(List.of(), only("NW011", server("proxy_ssl_verify on;\nlocation / {\n  proxy_pass https://api.internal;\n}")), "inherited");
		assertEquals(List.of("NW011:6"), only("NW011", server("proxy_ssl_verify on;\nlocation / {\n  proxy_ssl_verify off;\n  proxy_pass https://api.internal;\n}")));
		assertEquals(List.of(), only("NW011", server("proxy_pass http://api.internal;")));
		assertEquals(List.of("NW011:3"), only("NW011", server("proxy_pass HTTPS://api.internal;")));
	}

	// ---- NW009 / NW010 -----------------------------------------------------

	@Test
	void stubStatus() throws IOException {
		assertEquals(List.of("NW009:4"), only("NW009", server("location /status {\n  stub_status;\n}")));
		assertEquals(List.of(), only("NW009", server("location /status {\n  stub_status;\n  allow 127.0.0.1;\n  deny all;\n}")));
		assertEquals(List.of(), only("NW009", server("location /status {\n  stub_status;\n  auth_basic \"x\";\n  auth_basic_user_file /etc/p;\n}")));
		assertEquals(List.of("NW009:4"), only("NW009", server("location /status {\n  stub_status;\n  auth_basic off;\n}")));
		assertEquals(List.of(), only("NW009", server("allow 10.0.0.0/8;\ndeny all;\nlocation /status {\n  stub_status;\n}")), "inherited");
	}

	@Test
	void unlimitedBody() throws IOException {
		assertEquals(List.of("NW010:3"), only("NW010", server("client_max_body_size 0;")));
		assertEquals(List.of("NW010:3"), only("NW010", server("client_max_body_size 0m;")));
		assertEquals(List.of(), only("NW010", server("client_max_body_size 10m;")));
		assertEquals(List.of(), only("NW010", server("client_max_body_size 100m;")), "0 only: 100m ends in 0 but is a limit");
	}

	// ---- NW012 -------------------------------------------------------------

	@Test
	void corsReflection() throws IOException {
		assertEquals(List.of("NW012:3"), only("NW012", server("add_header Access-Control-Allow-Origin $http_origin always;")));
		assertEquals(List.of("NW012:3"), only("NW012", server("add_header Access-Control-Allow-Origin ${http_origin};")));
		assertEquals(List.of(), only("NW012", server("add_header Access-Control-Allow-Origin https://app.example.com always;")));
		assertEquals(List.of(), only("NW012", server("add_header Access-Control-Allow-Origin $cors_origin always;")), "a mapped variable is an allow-list");
		assertEquals(List.of(), only("NW012", server("add_header Access-Control-Allow-Origin * always;")));
	}

	@Test
	void corsReflectionWithCredentialsIsCritical() throws IOException {
		Path file = dir.resolve("nginx.conf");
		Files.writeString(file, server("add_header Access-Control-Allow-Origin $http_origin always;\nadd_header Access-Control-Allow-Credentials true always;"));
		List<Finding> f = Rules.run(new Parser(dir).parseFile(file)).stream().filter(x -> x.rule().equals("NW012")).toList();
		assertEquals(1, f.size());
		assertEquals(Severity.CRITICAL, f.get(0).severity());
		assertTrue(f.get(0).message().contains("credentials"));
	}

	// ---- NW013 / NW014 -----------------------------------------------------

	@Test
	void documentRootAtASystemDirectory() throws IOException {
		assertEquals(List.of("NW013:3"), only("NW013", server("root /;")));
		assertEquals(List.of("NW013:3"), only("NW013", server("root /etc/;")));
		assertEquals(List.of("NW013:3"), only("NW013", server("root /home;")));
		assertEquals(List.of(), only("NW013", server("root /var/www/html;")));
		assertEquals(List.of(), only("NW013", server("root /srv/app/public;")));
	}

	@Test
	void workersAsRoot() throws IOException {
		assertEquals(List.of("NW014:1"), only("NW014", "user root;\nevents { }\n"));
		assertEquals(List.of("NW014:1"), only("NW014", "user root root;\n"));
		assertEquals(List.of(), only("NW014", "user www-data;\n"));
		assertEquals(List.of(), only("NW014", "user nginx nginx;\n"));
	}

	// ---- structure ---------------------------------------------------------

	@Test
	void everyRuleIsDocumentedAndIdsAreOrdered() {
		String prev = "";
		for (Rule r : Rules.ALL) {
			assertTrue(r.id().compareTo(prev) > 0, r.id() + " out of order");
			prev = r.id();
			assertTrue(!r.name().isEmpty() && !r.title().isEmpty() && !r.why().isEmpty() && !r.fix().isEmpty(), r.id());
		}
		assertEquals(14, Rules.ALL.size());
	}

	@Test
	void anIncludedSnippetIsJudgedInTheContextItIsIncludedIn() throws IOException {
		Files.writeString(dir.resolve("headers.conf"), "add_header Cache-Control public;\n");
		Path file = dir.resolve("nginx.conf");
		Files.writeString(file, server("add_header X-Frame-Options DENY always;\nlocation /a {\n  include headers.conf;\n}"));
		List<Finding> f = Rules.run(new Parser(dir).parseFile(file)).stream().filter(x -> x.rule().equals("NW002")).toList();
		assertEquals(1, f.size());
		assertTrue(f.get(0).file().endsWith("headers.conf"), "reported at the add_header, in the snippet");
	}
}
