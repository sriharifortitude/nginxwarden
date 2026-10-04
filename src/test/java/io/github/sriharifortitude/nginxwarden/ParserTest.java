package io.github.sriharifortitude.nginxwarden;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ParserTest {

	@TempDir
	Path dir;

	private Directive parse(String conf) throws IOException {
		Path file = dir.resolve("nginx.conf");
		Files.writeString(file, conf);
		return new Parser(dir).parseFile(file);
	}

	private static List<String> texts(Directive d) {
		return d.args.stream().map(Directive.Arg::text).toList();
	}

	@Test
	void directivesAndBlocksNestWithParentsAndLines() throws IOException {
		Directive root = parse("user www;\nhttp {\n  server {\n    listen 80;\n  }\n}\n");
		Directive http = root.children.get(1);
		Directive server = http.children.get(0);
		Directive listen = server.children.get(0);
		assertEquals("listen", listen.name);
		assertEquals(List.of("80"), texts(listen));
		assertEquals(4, listen.line);
		assertEquals(server, listen.parent);
		assertEquals(http, server.enclosing("http"));
		assertTrue(http.isBlock());
		assertFalse(listen.isBlock());
	}

	@Test
	void commentsAreSkippedEvenAfterADirective() throws IOException {
		Directive root = parse("# header\nworker_processes 4; # trailing\n#server { listen 80; }\n");
		assertEquals(1, root.children.size());
		assertEquals(List.of("4"), texts(root.children.get(0)));
	}

	@Test
	void quotesKeepSpacesSemicolonsAndBraces() throws IOException {
		Directive root = parse("add_header X-A \"a; b {c}\";\nadd_header X-B 'it\\'s';\nset $x \"tab\\there\";\n");
		assertEquals(List.of("X-A", "a; b {c}"), texts(root.children.get(0)));
		assertTrue(root.children.get(0).args.get(1).quoted());
		assertEquals(List.of("X-B", "it's"), texts(root.children.get(1)));
		assertEquals("tab\there", root.children.get(2).arg(1));
	}

	@Test
	void aVariableInBracesIsPartOfTheWordNotABlock() throws IOException {
		Directive root = parse("set $upstream http://${host}:8080;\nproxy_pass http://backend${request_uri};\n");
		assertEquals(List.of("$upstream", "http://${host}:8080"), texts(root.children.get(0)));
		assertEquals("http://backend${request_uri}", root.children.get(1).arg(0));
	}

	@Test
	void aQuotedRegexWithBracesIsOneArgument() throws IOException {
		Directive root = parse("location ~ \"^/v[0-9]{2}/\" { return 200; }\n");
		assertEquals(List.of("~", "^/v[0-9]{2}/"), texts(root.children.get(0)));
		assertEquals(1, root.children.get(0).children.size());
	}

	@Test
	void luaBlocksAreSkippedNotParsedAsDirectives() throws IOException {
		Directive root = parse("location / {\n  content_by_lua_block {\n    local t = { a = 1 }\n    ngx.say(\"x; y\")\n  }\n  return 200;\n}\n");
		Directive location = root.children.get(0);
		assertEquals(List.of("content_by_lua_block", "return"), location.children.stream().map(d -> d.name).toList());
		assertTrue(location.children.get(0).children.isEmpty());
	}

	@Test
	void effectiveFindsTheNearestEnclosingBlockThatSetsIt() throws IOException {
		Directive root = parse("http { server_tokens off; server { location /a { } location /b { server_tokens on; } } }\n");
		Directive http = root.children.get(0);
		Directive a = http.children.get(1).children.get(0);
		Directive b = http.children.get(1).children.get(1);
		assertEquals("off", a.effective("server_tokens").get(0).arg(0));
		assertEquals("on", b.effective("server_tokens").get(0).arg(0));
		assertTrue(a.effective("nothing").isEmpty());
	}

	@Test
	void syntaxErrorsNameTheFileAndTheLine() throws IOException {
		for (String[] c : new String[][] {
				{ "http {\n  listen 80\n}\n", "nginx.conf:3: unexpected \"}\"" },
				{ "http {\n  listen 80;\n", "unexpected end of file, expecting \"}\"" },
				{ "listen 80", "unexpected end of file, expecting \";\" or \"}\" after \"listen\"" },
				{ "}\n", "nginx.conf:1: unexpected \"}\"" },
				{ ";\n", "nginx.conf:1: unexpected \";\"" },
				{ "add_header X \"never closed;\n", "line 1: unterminated double-quoted string" },
				{ "set $x ${never;\n", "unterminated ${ variable" },
		}) {
			ConfigException e = assertThrows(ConfigException.class, () -> parse(c[0]), c[0]);
			assertTrue(e.getMessage().contains(c[1]), c[0] + " -> " + e.getMessage());
		}
	}

	@Test
	void deepNestingIsRefusedNotAStackOverflow() {
		String conf = "a {".repeat(200) + "}".repeat(200);
		ConfigException e = assertThrows(ConfigException.class, () -> parse(conf));
		assertTrue(e.getMessage().contains("nested more than"));
	}

	// ---- include -----------------------------------------------------------------

	@Test
	void includeSplicesFilesInPlaceAndInOrder() throws IOException {
		Files.createDirectories(dir.resolve("conf.d"));
		Files.writeString(dir.resolve("conf.d/b.conf"), "server { listen 2; }\n");
		Files.writeString(dir.resolve("conf.d/a.conf"), "server { listen 1; }\n");
		Files.writeString(dir.resolve("conf.d/notes.txt"), "server { listen 99; }\n");
		Directive root = parse("http {\n  include conf.d/*.conf;\n  server_tokens off;\n}\n");
		Directive http = root.children.get(0);
		assertEquals(List.of("server", "server", "server_tokens"), http.children.stream().map(d -> d.name).toList());
		assertEquals("1", http.children.get(0).children.get(0).arg(0));
		assertEquals(http, http.children.get(0).parent);
		assertTrue(http.children.get(0).file.endsWith("a.conf"));
	}

	@Test
	void includesResolveRelativeToThePrefixAndAbsolutePathsWork() throws IOException {
		Files.writeString(dir.resolve("snippet.conf"), "autoindex on;\n");
		Path abs = dir.resolve("abs.conf");
		Files.writeString(abs, "client_max_body_size 0;\n");
		Directive root = parse("include snippet.conf;\ninclude " + abs.toString().replace('\\', '/') + ";\n");
		assertEquals(List.of("autoindex", "client_max_body_size"), root.children.stream().map(d -> d.name).toList());
	}

	@Test
	void anIncludeThatMatchesNothingIsANoteNotAnError() throws IOException {
		Path file = dir.resolve("nginx.conf");
		Files.writeString(file, "include /etc/nginx/mime.types;\ninclude missing/*.conf;\nworker_processes 1;\n");
		Parser parser = new Parser(dir);
		Directive root = parser.parseFile(file);
		assertEquals(1, root.children.size());
		assertEquals(2, parser.unresolvedIncludes.size());
		assertTrue(parser.unresolvedIncludes.get(1).contains("include missing/*.conf matched no file"));
	}

	@Test
	void anIncludeWithACharacterThatIsIllegalInAPathDoesNotCrash() throws IOException {
		Path file = dir.resolve("nginx.conf");
		Files.writeString(file, "include \"a<b>|c?.conf\";\ninclude \"con:aux/*.conf\";\n");
		Parser parser = new Parser(dir);
		parser.parseFile(file);
		assertEquals(2, parser.unresolvedIncludes.size());
	}

	@Test
	void anIncludeWithAVariableIsKeptAsADirective() throws IOException {
		Directive root = parse("include /etc/nginx/$site.conf;\n");
		assertEquals("include", root.children.get(0).name);
	}

	@Test
	void anIncludeCycleIsAnErrorNotAnInfiniteLoop() throws IOException {
		Files.writeString(dir.resolve("a.conf"), "include b.conf;\n");
		Files.writeString(dir.resolve("b.conf"), "include a.conf;\n");
		ConfigException e = assertThrows(ConfigException.class, () -> new Parser(dir).parseFile(dir.resolve("a.conf")));
		assertTrue(e.getMessage().contains("includes itself"), e.getMessage());
	}

	@Test
	void aSyntaxErrorInAnIncludedFileNamesThatFile() throws IOException {
		Files.writeString(dir.resolve("bad.conf"), "server {\n  listen 80\n}\n");
		ConfigException e = assertThrows(ConfigException.class, () -> parse("include bad.conf;\n"));
		assertTrue(e.getMessage().contains("bad.conf:3: unexpected \"}\""), e.getMessage());
	}

	@Test
	void aMissingFileAndABinaryFileAreErrors() throws IOException {
		assertThrows(ConfigException.class, () -> new Parser(dir).parseFile(dir.resolve("nope.conf")));
		Path bin = dir.resolve("bin.conf");
		Files.write(bin, new byte[] { 'a', ' ', (byte) 0xff, (byte) 0xfe, ';' });
		ConfigException e = assertThrows(ConfigException.class, () -> new Parser(dir).parseFile(bin));
		assertTrue(e.getMessage().contains("not valid UTF-8"));
	}

	@Test
	void aByteOrderMarkIsTolerated() throws IOException {
		Path file = dir.resolve("bom.conf");
		Files.writeString(file, "﻿user www;\n");
		assertEquals("user", new Parser(dir).parseFile(file).children.get(0).name);
	}
}
