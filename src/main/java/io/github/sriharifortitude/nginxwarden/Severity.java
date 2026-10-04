package io.github.sriharifortitude.nginxwarden;

import java.util.Locale;
import java.util.Optional;

enum Severity {
	LOW, MEDIUM, HIGH, CRITICAL;

	String label() {
		return name().toLowerCase(Locale.ROOT);
	}

	static Optional<Severity> parse(String s) {
		for (Severity v : values()) {
			if (v.label().equals(s)) {
				return Optional.of(v);
			}
		}
		return Optional.empty();
	}
}
