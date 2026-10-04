package io.github.sriharifortitude.nginxwarden;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Terminal, JSON and SARIF output. All three are deterministic. */
final class Report {

	private Report() {
	}

	static String summary(Scanner.Result r) {
		List<String> parts = new ArrayList<>();
		for (Severity s : new Severity[] { Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW }) {
			long n = r.findings().stream().filter(f -> f.severity() == s).count();
			if (n > 0) {
				parts.add(n + " " + s.label());
			}
		}
		String text = r.findings().size() + " finding(s): " + (parts.isEmpty() ? "none" : String.join(", ", parts))
				+ ", in " + r.roots().size() + " configuration(s)";
		if (r.suppressed() > 0) {
			text += "; " + r.suppressed() + " suppressed with a reason";
		}
		return text;
	}

	private static String title(String rule) {
		if (rule.equals(Rules.META_ID)) {
			return "suppression comment without a reason";
		}
		return Rules.byId(rule).map(Rule::title).orElse(rule);
	}

	private static String fix(String rule) {
		if (rule.equals(Rules.META_ID)) {
			return Rules.META_FIX;
		}
		return Rules.byId(rule).map(Rule::fix).orElse("");
	}

	static String terminal(Scanner.Result r, boolean brief) {
		StringBuilder sb = new StringBuilder();
		for (Finding f : r.findings()) {
			String head = String.format(Locale.ROOT, "%s:%d  %-8s %s  ", f.file(), f.line(), f.severity().label().toUpperCase(Locale.ROOT), f.rule());
			if (brief) {
				sb.append(head).append(f.message()).append('\n');
			} else {
				sb.append(head).append(title(f.rule())).append('\n').append("    ").append(f.message()).append('\n')
						.append("    fix: ").append(fix(f.rule())).append('\n');
			}
		}
		if (!r.findings().isEmpty()) {
			sb.append('\n');
		}
		sb.append(summary(r)).append('\n');
		return sb.toString();
	}

	static String json(Scanner.Result r) {
		Map<String, Object> doc = new LinkedHashMap<>();
		doc.put("configurations", r.roots().size());
		doc.put("suppressed", r.suppressed());
		List<Object> findings = new ArrayList<>();
		for (Finding f : r.findings()) {
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("rule", f.rule());
			m.put("name", Rules.byId(f.rule()).map(Rule::name).orElse("ignore-without-reason"));
			m.put("severity", f.severity().label());
			m.put("file", f.file());
			m.put("line", f.line());
			m.put("message", f.message());
			m.put("fix", fix(f.rule()));
			findings.add(m);
		}
		doc.put("findings", findings);
		doc.put("errors", new ArrayList<Object>(r.errors()));
		doc.put("notes", new ArrayList<Object>(r.notes()));
		return Json.write(doc);
	}

	private static String level(Severity s) {
		return switch (s) {
			case CRITICAL, HIGH -> "error";
			case MEDIUM -> "warning";
			case LOW -> "note";
		};
	}

	static String sarif(Scanner.Result r) {
		List<Object> descriptors = new ArrayList<>();
		descriptors.add(descriptor(Rules.META_ID, "ignore-without-reason", title(Rules.META_ID),
				"A suppression nobody can explain is a finding nobody will revisit.", Rules.META_FIX, Severity.LOW));
		for (Rule rule : Rules.ALL) {
			descriptors.add(descriptor(rule.id(), rule.name(), rule.title(), rule.why(), rule.fix(), rule.severity()));
		}
		List<Object> results = new ArrayList<>();
		for (Finding f : r.findings()) {
			Map<String, Object> region = new LinkedHashMap<>();
			region.put("startLine", f.line());
			Map<String, Object> artifact = new LinkedHashMap<>();
			artifact.put("uri", f.file());
			Map<String, Object> physical = new LinkedHashMap<>();
			physical.put("artifactLocation", artifact);
			physical.put("region", region);
			Map<String, Object> location = new LinkedHashMap<>();
			location.put("physicalLocation", physical);
			Map<String, Object> result = new LinkedHashMap<>();
			result.put("ruleId", f.rule());
			result.put("level", level(f.severity()));
			result.put("message", Map.of("text", f.message()));
			result.put("locations", List.of(location));
			results.add(result);
		}
		Map<String, Object> driver = new LinkedHashMap<>();
		driver.put("name", "nginxwarden");
		driver.put("informationUri", "https://github.com/sriharifortitude/nginxwarden");
		driver.put("rules", descriptors);
		Map<String, Object> run = new LinkedHashMap<>();
		run.put("tool", Map.of("driver", driver));
		run.put("results", results);
		Map<String, Object> doc = new LinkedHashMap<>();
		doc.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
		doc.put("version", "2.1.0");
		doc.put("runs", List.of(run));
		return Json.write(doc);
	}

	private static Map<String, Object> descriptor(String id, String name, String title, String why, String fix, Severity severity) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("id", id);
		m.put("name", name);
		m.put("shortDescription", Map.of("text", title));
		m.put("fullDescription", Map.of("text", why));
		m.put("help", Map.of("text", fix));
		m.put("defaultConfiguration", Map.of("level", level(severity)));
		return m;
	}
}
