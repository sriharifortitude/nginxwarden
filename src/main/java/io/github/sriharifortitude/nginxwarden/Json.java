package io.github.sriharifortitude.nginxwarden;

import java.util.List;
import java.util.Map;

/** A small JSON writer, so the program needs no dependencies. Maps keep their order. */
final class Json {

	private Json() {
	}

	static String write(Object value) {
		StringBuilder sb = new StringBuilder();
		write(sb, value, 0);
		return sb.append('\n').toString();
	}

	private static void indent(StringBuilder sb, int level) {
		sb.append("  ".repeat(level));
	}

	private static void write(StringBuilder sb, Object v, int level) {
		switch (v) {
			case null -> sb.append("null");
			case String s -> string(sb, s);
			case Integer i -> sb.append(i);
			case Long l -> sb.append(l);
			case Boolean b -> sb.append(b);
			case Map<?, ?> m -> {
				if (m.isEmpty()) {
					sb.append("{}");
					return;
				}
				sb.append("{\n");
				int n = 0;
				for (Map.Entry<?, ?> e : m.entrySet()) {
					indent(sb, level + 1);
					string(sb, String.valueOf(e.getKey()));
					sb.append(": ");
					write(sb, e.getValue(), level + 1);
					sb.append(++n < m.size() ? ",\n" : "\n");
				}
				indent(sb, level);
				sb.append('}');
			}
			case List<?> list -> {
				if (list.isEmpty()) {
					sb.append("[]");
					return;
				}
				sb.append("[\n");
				for (int i = 0; i < list.size(); i++) {
					indent(sb, level + 1);
					write(sb, list.get(i), level + 1);
					sb.append(i + 1 < list.size() ? ",\n" : "\n");
				}
				indent(sb, level);
				sb.append(']');
			}
			default -> throw new IllegalArgumentException("cannot write " + v.getClass());
		}
	}

	private static void string(StringBuilder sb, String s) {
		sb.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					} else {
						sb.append(c);
					}
				}
			}
		}
		sb.append('"');
	}
}
