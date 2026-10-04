package io.github.sriharifortitude.nginxwarden;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/** Finds configurations, runs the rules, and applies suppression comments. */
final class Scanner {

	/** Everything a scan produced. */
	record Result(List<Finding> findings, int suppressed, List<String> roots, List<String> errors, List<String> notes) {
	}

	private static final Set<String> SKIP_DIRS = Set.of(".git", "node_modules", "build", "target", ".gradle", "vendor");
	private static final Pattern DIRECTIVE = Pattern.compile("#\\s*nginxwarden:ignore\\s+(NW\\d{3})(?=[\\s:]|$)(.*)$");

	private Scanner() {
	}

	/** Root configuration files for the paths given: a file is its own root; a directory yields its nginx.conf files, or else its .conf files. */
	static List<Path> roots(List<Path> inputs) {
		List<Path> roots = new ArrayList<>();
		for (Path p : inputs) {
			if (Files.isRegularFile(p)) {
				roots.add(p);
			} else if (Files.isDirectory(p)) {
				List<Path> main = new ArrayList<>();
				List<Path> any = new ArrayList<>();
				walk(p, main, any);
				roots.addAll(main.isEmpty() ? any : main);
			} else {
				throw new ConfigException(p.toString().replace('\\', '/') + ": no such file or directory");
			}
		}
		return roots;
	}

	private static void walk(Path dir, List<Path> main, List<Path> any) {
		try (Stream<Path> entries = Files.list(dir)) {
			for (Path e : entries.sorted().toList()) {
				String name = e.getFileName().toString();
				if (Files.isDirectory(e)) {
					if (!SKIP_DIRS.contains(name)) {
						walk(e, main, any);
					}
				} else if (name.equals("nginx.conf")) {
					main.add(e);
				} else if (name.toLowerCase(Locale.ROOT).endsWith(".conf")) {
					any.add(e);
				}
			}
		} catch (IOException e) {
			throw new ConfigException(dir.toString().replace('\\', '/') + ": cannot read directory");
		}
	}

	static Result scan(List<Path> inputs, Path prefixOverride) {
		List<Path> roots = roots(inputs);
		Set<Finding> found = new LinkedHashSet<>();
		List<String> errors = new ArrayList<>();
		List<String> notes = new ArrayList<>();
		List<String> scanned = new ArrayList<>();
		int suppressed = 0;
		Map<String, List<String>> sources = new HashMap<>();
		for (Path root : roots) {
			Path prefix = prefixOverride != null ? prefixOverride : (root.toAbsolutePath().getParent() == null ? Path.of(".") : root.toAbsolutePath().getParent());
			Parser parser = new Parser(prefix);
			try {
				Directive tree = parser.parseFile(root);
				scanned.add(root.toString().replace('\\', '/'));
				notes.addAll(parser.unresolvedIncludes);
				found.addAll(Rules.run(tree));
			} catch (ConfigException e) {
				errors.add(e.getMessage());
			}
		}
		List<Finding> kept = new ArrayList<>();
		Set<String> reasonless = new LinkedHashSet<>();
		for (Finding f : found) {
			List<String> lines = sources.computeIfAbsent(f.file(), Scanner::readLines);
			Matcher m = null;
			int commentLine = 0;
			for (int candidate : new int[] { f.line(), f.line() - 1 }) {
				if (candidate < 1 || candidate > lines.size()) {
					continue;
				}
				String text = lines.get(candidate - 1);
				if (candidate == f.line() - 1 && !text.trim().startsWith("#")) {
					continue;
				}
				Matcher attempt = DIRECTIVE.matcher(text.substring(Math.max(0, text.indexOf('#') < 0 ? text.length() : text.indexOf('#'))));
				if (attempt.find() && attempt.group(1).equals(f.rule())) {
					m = attempt;
					commentLine = candidate;
					break;
				}
			}
			if (m == null) {
				kept.add(f);
				continue;
			}
			String reason = m.group(2).trim();
			if (reason.startsWith("--")) {
				reason = reason.substring(2).trim();
			} else if (reason.startsWith(":")) {
				reason = reason.substring(1).trim();
			}
			if (!reason.isEmpty()) {
				suppressed++;
				continue;
			}
			kept.add(f);
			if (reasonless.add(f.file() + ":" + commentLine)) {
				kept.add(new Finding(Rules.META_ID, Severity.LOW, f.file(), commentLine,
						"this comment suppresses " + f.rule() + " but gives no reason, so it suppresses nothing. " + Rules.META_FIX));
			}
		}
		kept.sort(Finding.ORDER);
		return new Result(kept, suppressed, scanned, errors, notes);
	}

	private static List<String> readLines(String file) {
		try {
			return Files.readAllLines(Path.of(file), StandardCharsets.UTF_8);
		} catch (IOException | RuntimeException e) {
			return List.of();
		}
	}
}
