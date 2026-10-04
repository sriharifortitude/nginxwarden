package io.github.sriharifortitude.nginxwarden;

import java.util.Comparator;

/** One problem at one place in one file. */
record Finding(String rule, Severity severity, String file, int line, String message) {

	static final Comparator<Finding> ORDER = Comparator.comparing(Finding::file)
			.thenComparingInt(Finding::line)
			.thenComparing(Finding::rule)
			.thenComparing(Finding::message);
}
