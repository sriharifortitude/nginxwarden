package io.github.sriharifortitude.nginxwarden;

import java.util.ArrayList;
import java.util.List;

/**
 * One directive: {@code name arg arg;} or {@code name arg { children }}.
 * The root of a file is a nameless block holding its top-level directives.
 */
final class Directive {

	record Arg(String text, boolean quoted) {
	}

	final String name;
	final List<Arg> args;
	final int line;
	final String file;
	/** Null for a simple directive; the (possibly empty) child list for a block. */
	final List<Directive> children;
	Directive parent;

	Directive(String name, List<Arg> args, int line, String file, List<Directive> children) {
		this.name = name;
		this.args = args;
		this.line = line;
		this.file = file;
		this.children = children;
	}

	static Directive root(String file) {
		return new Directive("", List.of(), 1, file, new ArrayList<>());
	}

	boolean isBlock() {
		return children != null;
	}

	String arg(int i) {
		return i < args.size() ? args.get(i).text() : null;
	}

	/** Whether any argument equals {@code value}, ignoring case. */
	boolean hasArg(String value) {
		return args.stream().anyMatch(a -> a.text().equalsIgnoreCase(value));
	}

	/** Direct children with this name. */
	List<Directive> childrenNamed(String directive) {
		List<Directive> out = new ArrayList<>();
		if (children != null) {
			for (Directive d : children) {
				if (d.name.equals(directive)) {
					out.add(d);
				}
			}
		}
		return out;
	}

	/** The directives of {@code name} in the nearest enclosing block that has any: nginx's rule for inherited settings. */
	List<Directive> effective(String directive) {
		Directive scope = isBlock() ? this : parent;
		while (scope != null) {
			List<Directive> here = scope.childrenNamed(directive);
			if (!here.isEmpty()) {
				return here;
			}
			scope = scope.parent;
		}
		return List.of();
	}

	/** The nearest enclosing block with this name, starting from this directive's parent. */
	Directive enclosing(String blockName) {
		Directive scope = parent;
		while (scope != null) {
			if (scope.name.equals(blockName)) {
				return scope;
			}
			scope = scope.parent;
		}
		return null;
	}

	/** Every directive in this subtree, this one first. */
	void walk(java.util.function.Consumer<Directive> visitor) {
		visitor.accept(this);
		if (children != null) {
			for (Directive d : new ArrayList<>(children)) {
				d.walk(visitor);
			}
		}
	}

	@Override
	public String toString() {
		return name + " " + args.stream().map(Arg::text).toList();
	}
}
