package io.github.sriharifortitude.nginxwarden;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** The command line, written so tests can call {@link #run} instead of starting a process. */
final class Cli {

	static final String USAGE = """
			usage: nginxwarden scan [--format terminal|json|sarif] [--brief] [--fail-on LEVEL]
			                        [--prefix DIR] [PATH...]
			       nginxwarden rules

			  scan     check nginx configuration. PATH is a file, or a directory searched for
			           nginx.conf (or, if there is none, for *.conf). include directives are
			           followed. With no PATH, the current directory.
			  rules    list every rule with why it matters and how to fix it

			  --format    terminal (default), json, or sarif for GitHub code scanning
			  --brief     terminal format: one line per finding, without the fix
			  --fail-on   lowest severity that makes the exit code 1: low, medium, high
			              (default), critical, or none
			  --prefix    directory that relative include paths are resolved against
			              (default: the directory of each configuration file)

			exit codes: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage
			error or a file that could not be read

			suppress a finding with a reason, on its line or the line above:
			  # nginxwarden:ignore NW011 -- upstream is on the loopback interface""";

	private Cli() {
	}

	/** Run and return the exit code. */
	static int run(String[] args, PrintStream out, PrintStream err) {
		try {
			return dispatch(args, out, err);
		} catch (UsageException | ConfigException e) {
			err.println("nginxwarden: " + e.getMessage());
			if (e instanceof UsageException) {
				err.println();
				err.println(USAGE);
			}
			return 2;
		}
	}

	private static final class UsageException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		UsageException(String message) {
			super(message);
		}
	}

	private static int dispatch(String[] args, PrintStream out, PrintStream err) {
		if (args.length == 0) {
			throw new UsageException("no command given");
		}
		switch (args[0]) {
			case "rules" -> {
				if (args.length > 1) {
					throw new UsageException("rules takes no arguments");
				}
				out.print(listRules());
				return 0;
			}
			case "scan" -> {
				return scan(java.util.Arrays.copyOfRange(args, 1, args.length), out, err);
			}
			case "-h", "--help", "help" -> {
				out.println(USAGE);
				return 0;
			}
			default -> throw new UsageException("unknown command \"" + args[0] + "\"");
		}
	}

	static String listRules() {
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		for (Rule r : Rules.ALL) {
			if (!first) {
				sb.append('\n');
			}
			first = false;
			sb.append(String.format(java.util.Locale.ROOT, "%s  %-8s %s (%s)%n    why: %s%n    fix: %s%n",
					r.id(), r.severity().label().toUpperCase(java.util.Locale.ROOT), r.title(), r.name(), r.why(), r.fix()));
		}
		return sb.toString();
	}

	private static int scan(String[] args, PrintStream out, PrintStream err) {
		String format = "terminal";
		boolean brief = false;
		Optional<Severity> failOn = Optional.of(Severity.HIGH);
		Path prefix = null;
		List<Path> paths = new ArrayList<>();
		for (int i = 0; i < args.length; i++) {
			String arg = args[i];
			String flag = arg;
			String inline = null;
			if (arg.startsWith("--") && arg.contains("=")) {
				flag = arg.substring(0, arg.indexOf('='));
				inline = arg.substring(arg.indexOf('=') + 1);
			}
			switch (flag) {
				case "--format" -> {
					format = value(args, i, flag, inline);
					i += inline == null ? 1 : 0;
					if (!List.of("terminal", "json", "sarif").contains(format)) {
						throw new UsageException("unknown format \"" + format + "\"");
					}
				}
				case "--brief" -> brief = true;
				case "--fail-on" -> {
					String v = value(args, i, flag, inline);
					i += inline == null ? 1 : 0;
					if (v.equals("none")) {
						failOn = Optional.empty();
					} else {
						failOn = Optional.of(Severity.parse(v).orElseThrow(() -> new UsageException("unknown severity \"" + v + "\"")));
					}
				}
				case "--prefix" -> {
					prefix = Path.of(value(args, i, flag, inline));
					i += inline == null ? 1 : 0;
				}
				default -> {
					if (arg.startsWith("--")) {
						throw new UsageException("unknown option " + arg);
					}
					paths.add(Path.of(arg));
				}
			}
		}
		if (paths.isEmpty()) {
			paths.add(Path.of("."));
		}

		Scanner.Result result = Scanner.scan(paths, prefix);
		for (String e : result.errors()) {
			err.println("nginxwarden: " + e);
		}
		for (String n : result.notes()) {
			err.println("nginxwarden: note: " + n);
		}
		if (result.roots().isEmpty() && result.errors().isEmpty()) {
			throw new UsageException("no nginx configuration found in " + String.join(", ", paths.stream().map(p -> p.toString().replace('\\', '/')).toList()));
		}
		String text = switch (format) {
			case "json" -> Report.json(result);
			case "sarif" -> Report.sarif(result);
			default -> Report.terminal(result, brief);
		};
		out.print(text);
		out.flush();
		if (!result.errors().isEmpty()) {
			err.println("nginxwarden: " + result.errors().size() + " file(s) could not be read and are not covered by the result above");
			return 2;
		}
		if (failOn.isPresent()) {
			Severity threshold = failOn.get();
			if (result.findings().stream().anyMatch(f -> f.severity().compareTo(threshold) >= 0)) {
				return 1;
			}
		}
		return 0;
	}

	private static String value(String[] args, int i, String flag, String inline) {
		if (inline != null) {
			return inline;
		}
		if (i + 1 >= args.length) {
			throw new UsageException(flag + " needs a value");
		}
		return args[i + 1];
	}

	static PrintStream utf8(java.io.OutputStream stream) {
		return new PrintStream(stream, true, StandardCharsets.UTF_8);
	}
}
