package io.github.sriharifortitude.nginxwarden;

import java.util.List;
import java.util.function.Function;

/** A check and the text a person needs to understand and fix what it found. */
record Rule(String id, String name, String title, Severity severity, String why, String fix,
		Function<Directive, List<Finding>> check) {
}
