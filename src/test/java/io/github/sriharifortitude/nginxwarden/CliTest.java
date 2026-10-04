package io.github.sriharifortitude.nginxwarden;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CliTest {

	@TempDir
	Path dir;

	private record Out(int code, String out, String err) {
	}

	private static Out run(String... args) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ByteArrayOutputStream err = new ByteArrayOutputStream();
		int code = Cli.run(args, Cli.utf8(out), Cli.utf8(err));
		return new Out(code, out.toString(StandardCharsets.UTF_8).replace("\r\n", "\n"), err.toString(StandardCharsets.UTF_8).replace("\r\n", "\n"));
	}

	private static final String VULNERABLE = "testdata/vulnerable";
	private static final String CLEAN = "testdata/clean";

	@Test
	void theVulnerableFixtureIsReportedWithLinesAcrossAnInclude() {
		Out r = run("scan", "--brief", VULNERABLE);
		assertEquals(1, r.code);
		for (String expected : List.of(
				"testdata/vulnerable/nginx.conf:1  MEDIUM   NW014",
				"testdata/vulnerable/nginx.conf:25  HIGH     NW001",
				"testdata/vulnerable/nginx.conf:35  CRITICAL NW012",
				"testdata/vulnerable/nginx.conf:40  HIGH     NW008",
				"testdata/vulnerable/nginx.conf:50  HIGH     NW013",
				"testdata/vulnerable/conf.d/admin.conf:1  MEDIUM   NW007",
				"16 finding(s): 1 critical, 5 high, 8 medium, 2 low, in 1 configuration(s)")) {
			assertTrue(r.out.contains(expected), "missing " + expected + "\n" + r.out);
		}
		assertTrue(r.err.contains("include mime.types matched no file"), "an include that matches nothing is a note");
	}

	@Test
	void theCleanFixturePassesAtTheStrictestLevel() {
		Out r = run("scan", "--fail-on", "low", CLEAN);
		assertEquals(0, r.code, r.out);
		assertTrue(r.out.contains("0 finding(s): none, in 1 configuration(s)"));
		assertEquals("", r.err);
	}

	@Test
	void failOnSetsTheExitCode() {
		int[] codes = new int[5];
		String[] levels = { "low", "medium", "high", "critical", "none" };
		for (int i = 0; i < levels.length; i++) {
			codes[i] = run("scan", "--fail-on", levels[i], VULNERABLE).code;
		}
		assertEquals(List.of(1, 1, 1, 1, 0), java.util.Arrays.stream(codes).boxed().toList());
		assertEquals(1, run("scan", "--fail-on=critical", VULNERABLE).code, "one critical finding exists");
	}

	@Test
	void briefDropsTheFixAndNothingElse() {
		String full = run("scan", VULNERABLE).out;
		String brief = run("scan", "--brief", VULNERABLE).out;
		assertTrue(full.contains("    fix: ") && !brief.contains("fix:"));
		assertEquals(18, brief.chars().filter(c -> c == '\n').count(), "16 findings, a blank line, the summary");
	}

	@Test
	void jsonIsCompleteAndEmptyListsAreLists() {
		String json = run("scan", "--format", "json", VULNERABLE).out;
		assertTrue(json.contains("\"configurations\": 1"));
		assertEquals(16, json.split("\"rule\":", -1).length - 1);
		assertTrue(json.contains("\"errors\": []"));
		assertTrue(json.contains("\"notes\": [\n    \"testdata/vulnerable/nginx.conf:10: include mime.types matched no file\""));
		String clean = run("scan", "--format=json", CLEAN).out;
		assertTrue(clean.contains("\"findings\": []") && clean.contains("\"errors\": []"));
	}

	@Test
	void sarifHasRulesResultsAndLevels() {
		String sarif = run("scan", "--format", "sarif", VULNERABLE).out;
		assertTrue(sarif.contains("\"version\": \"2.1.0\"") && sarif.contains("\"name\": \"nginxwarden\""));
		assertEquals(15, sarif.split("\"shortDescription\"", -1).length - 1, "14 rules plus NW000");
		// Levels appear on each result and on each rule's default: 6 error results + 5 high-default rules,
		// 8 warning results + 7 medium-default rules, 2 note results + 3 low-default rules (with NW000).
		assertEquals(11, sarif.split("\"level\": \"error\"", -1).length - 1);
		assertEquals(15, sarif.split("\"level\": \"warning\"", -1).length - 1);
		assertEquals(5, sarif.split("\"level\": \"note\"", -1).length - 1);
		assertTrue(sarif.contains("\"startLine\": 25"));
		assertFalse(sarif.contains("\\\\"), "no backslashes in uris");
	}

	@Test
	void outputIsDeterministic() {
		assertEquals(run("scan", VULNERABLE).out, run("scan", VULNERABLE).out);
	}

	@Test
	void theRulesCommandExplainsEveryRule() {
		String out = run("rules").out;
		assertEquals(14, out.split("    why: ", -1).length - 1);
		assertEquals(14, out.split("    fix: ", -1).length - 1);
		assertTrue(out.contains("NW001") && out.contains("off-by-slash"));
	}

	// ---- files and errors --------------------------------------------------------

	private Path write(String name, String text) throws IOException {
		Path p = dir.resolve(name);
		Files.createDirectories(p.getParent());
		Files.writeString(p, text);
		return p;
	}

	@Test
	void aDirectoryWithAnNginxConfIsRootedThereAndItsIncludesAreNotRootsToo() throws IOException {
		write("nginx.conf", "http { include conf.d/*.conf; }\n");
		write("conf.d/a.conf", "server { listen 80; autoindex on; }\n");
		Out r = run("scan", "--format", "json", dir.toString());
		assertTrue(r.out.contains("\"configurations\": 1"), r.out);
		assertEquals(1, r.out.split("NW006", -1).length - 1, "found once, through the include");
	}

	@Test
	void aDirectoryWithoutNginxConfScansEachConfFile() throws IOException {
		write("a.conf", "server { autoindex on; }\n");
		write("sub/b.conf", "server { autoindex on; }\n");
		write("node_modules/x.conf", "server { autoindex on; }\n");
		write("readme.txt", "server { autoindex on; }\n");
		Out r = run("scan", "--format", "json", dir.toString());
		assertTrue(r.out.contains("\"configurations\": 2"), r.out);
	}

	@Test
	void anInvalidFileIsNamedFailsTheRunAndTheRestIsStillScanned() throws IOException {
		write("a_good.conf", "server { autoindex on; }\n");
		write("b_bad.conf", "server {\n  listen 80\n}\n");
		Out r = run("scan", dir.toString());
		assertEquals(2, r.code);
		assertTrue(r.err.contains("b_bad.conf:3: unexpected \"}\""), r.err);
		assertTrue(r.err.contains("1 file(s) could not be read"), r.err);
		assertTrue(r.out.contains("NW006"), "the readable file is still reported");
	}

	@Test
	void anOversizedFileIsRefusedWithoutBeingRead() throws IOException {
		Path big = dir.resolve("big.conf");
		try (RandomAccessFile f = new RandomAccessFile(big.toFile(), "rw")) {
			f.setLength(Parser.MAX_FILE_BYTES + 1);
		}
		Out r = run("scan", big.toString());
		assertEquals(2, r.code);
		assertTrue(r.err.contains("larger than 8 MiB; refusing it"), r.err);
	}

	@Test
	void aMissingPathAndAnEmptyDirectoryAreErrors() throws IOException {
		Out missing = run("scan", dir.resolve("nope.conf").toString());
		assertEquals(2, missing.code);
		assertTrue(missing.err.contains("no such file or directory"));
		Out empty = run("scan", dir.toString());
		assertEquals(2, empty.code);
		assertTrue(empty.err.contains("no nginx configuration found"));
	}

	@Test
	void usageErrorsExitTwoWithUsage() {
		for (String[] args : new String[][] { {}, { "nope" }, { "scan", "--format", "xml" }, { "scan", "--fail-on", "urgent" },
				{ "scan", "--fail-on" }, { "scan", "--bogus" }, { "rules", "extra" } }) {
			Out r = run(args);
			assertEquals(2, r.code, String.join(" ", args));
			assertTrue(r.err.contains("usage: nginxwarden"), String.join(" ", args));
		}
	}

	@Test
	void prefixControlsWhereRelativeIncludesAreFound() throws IOException {
		Path conf = write("etc/site.conf", "include shared/snippet.conf;\n");
		write("shared/snippet.conf", "autoindex on;\n");
		Out without = run("scan", "--format", "json", conf.toString());
		assertTrue(without.out.contains("\"findings\": []"), "not found next to the file, so a note");
		Out with = run("scan", "--format", "json", "--prefix", dir.toString(), conf.toString());
		assertTrue(with.out.contains("NW006"), with.out);
	}

	// ---- suppression -------------------------------------------------------------

	private Map<String, Object> scan(String conf) throws IOException {
		Path file = write("s/nginx.conf", conf);
		Scanner.Result r = Scanner.scan(List.of(file), null);
		return Map.of("rules", r.findings().stream().map(Finding::rule).toList(), "suppressed", r.suppressed());
	}

	@Test
	void aSuppressionNeedsAReason() throws IOException {
		String line = "server { listen 443 ssl; add_header Strict-Transport-Security \"max-age=63072000\" always; proxy_pass https://a.internal; }";
		assertEquals(Map.of("rules", List.of("NW011"), "suppressed", 0), scan(line));
		assertEquals(Map.of("rules", List.of(), "suppressed", 1), scan("# nginxwarden:ignore NW011 -- loopback only\n" + line));
		assertEquals(Map.of("rules", List.of(), "suppressed", 1), scan(line + " # nginxwarden:ignore NW011 -- loopback only"));
		assertEquals(Map.of("rules", List.of(), "suppressed", 1), scan("# nginxwarden:ignore NW011: loopback only\n" + line));
		assertEquals(Map.of("rules", List.of("NW000", "NW011"), "suppressed", 0), scan("# nginxwarden:ignore NW011\n" + line));
		assertEquals(Map.of("rules", List.of("NW000", "NW011"), "suppressed", 0), scan("# nginxwarden:ignore NW011 --   \n" + line));
		assertEquals(Map.of("rules", List.of("NW011"), "suppressed", 0), scan("# nginxwarden:ignore NW010 -- wrong rule\n" + line));
		assertEquals(Map.of("rules", List.of("NW011"), "suppressed", 0), scan("# nginxwarden:ignore NW0111 -- longer id\n" + line));
		assertEquals(Map.of("rules", List.of("NW011"), "suppressed", 0), scan("# nginxwarden:ignore NW011 -- reason\n\n" + line), "a blank line breaks the link");
	}

	@Test
	void aSuppressionOnACodeLineAboveDoesNotCoverTheNextLine() throws IOException {
		String conf = "worker_processes 1; # nginxwarden:ignore NW014 -- no\nuser root;\n";
		assertEquals(Map.of("rules", List.of("NW014"), "suppressed", 0), scan(conf));
	}

	@Test
	void windowsLineEndingsAreHandled() throws IOException {
		assertEquals(Map.of("rules", List.of(), "suppressed", 1), scan("# nginxwarden:ignore NW014 -- ok\r\nuser root;\r\n"));
	}
}
