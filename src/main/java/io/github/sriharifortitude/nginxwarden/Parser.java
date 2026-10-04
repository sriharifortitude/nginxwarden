package io.github.sriharifortitude.nginxwarden;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Parses nginx configuration into a {@link Directive} tree, splicing in {@code include}d files. */
final class Parser {

	/** Largest file read. Real configurations are kilobytes. */
	static final long MAX_FILE_BYTES = 8L * 1024 * 1024;
	private static final int MAX_INCLUDE_DEPTH = 16;
	private static final int MAX_NESTING = 64;

	/** Include patterns that matched no file, with where they were written. Not errors: configs are often scanned away from /etc/nginx. */
	final List<String> unresolvedIncludes = new ArrayList<>();
	/** Every file read, in the order read. */
	final List<Path> filesRead = new ArrayList<>();

	private final Path prefix;
	private int pos;
	private List<Lexer.Token> tokens;
	private String currentFile;

	Parser(Path prefix) {
		this.prefix = prefix;
	}

	/** Parse one file and everything it includes. */
	Directive parseFile(Path file) {
		return parseFile(file, new ArrayList<>(), 0);
	}

	private Directive parseFile(Path file, List<Path> chain, int depth) {
		Path canonical;
		try {
			canonical = file.toRealPath();
		} catch (IOException e) {
			throw new ConfigException(file.toString().replace('\\', '/') + ": no such file");
		}
		if (chain.contains(canonical)) {
			throw new ConfigException(display(file) + ": includes itself (directly or through " + display(chain.get(chain.size() - 1)) + ")");
		}
		String text = read(canonical, file);
		filesRead.add(file);
		Directive root = Directive.root(display(file));
		List<Lexer.Token> savedTokens = tokens;
		int savedPos = pos;
		String savedFile = currentFile;
		try {
			tokens = Lexer.lex(text);
		} catch (ConfigException e) {
			throw new ConfigException(display(file) + ": " + e.getMessage());
		}
		pos = 0;
		currentFile = display(file);
		try {
			parseBlock(root, 0);
			if (pos < tokens.size()) {
				throw error(tokens.get(pos).line(), "unexpected \"}\"");
			}
			chain.add(canonical);
			spliceIncludes(root, file, chain, depth);
			chain.remove(chain.size() - 1);
		} finally {
			tokens = savedTokens;
			pos = savedPos;
			currentFile = savedFile;
		}
		return root;
	}

	/** The path as shown in findings: relative to the working directory when inside it, forward slashes always. */
	static String display(Path p) {
		Path abs = p.toAbsolutePath().normalize();
		Path cwd = Path.of("").toAbsolutePath().normalize();
		Path shown = abs.startsWith(cwd) && !abs.equals(cwd) ? cwd.relativize(abs) : abs;
		return shown.toString().replace('\\', '/');
	}

	private static String read(Path canonical, Path shown) {
		try {
			if (Files.size(canonical) > MAX_FILE_BYTES) {
				throw new ConfigException(display(shown) + ": larger than " + (MAX_FILE_BYTES >> 20) + " MiB; refusing it");
			}
			byte[] bytes = Files.readAllBytes(canonical);
			var decoder = StandardCharsets.UTF_8.newDecoder();
			String s = decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString();
			return s.startsWith("﻿") ? s.substring(1) : s;
		} catch (java.nio.charset.CharacterCodingException e) {
			throw new ConfigException(display(shown) + ": not valid UTF-8");
		} catch (IOException e) {
			throw new ConfigException(display(shown) + ": cannot read (" + e.getClass().getSimpleName() + ")");
		}
	}

	private ConfigException error(int line, String message) {
		return new ConfigException(currentFile + ":" + line + ": " + message);
	}

	/** Parse directives until a closing brace (consumed) or the end of the tokens. */
	private void parseBlock(Directive parent, int nesting) {
		if (nesting > MAX_NESTING) {
			throw error(pos < tokens.size() ? tokens.get(pos).line() : 1, "blocks nested more than " + MAX_NESTING + " deep");
		}
		while (pos < tokens.size()) {
			Lexer.Token t = tokens.get(pos);
			switch (t.kind()) {
				case RBRACE -> {
					if (nesting == 0) {
						return;
					}
					pos++;
					return;
				}
				case SEMICOLON -> throw error(t.line(), "unexpected \";\"");
				case LBRACE -> throw error(t.line(), "unexpected \"{\"");
				case WORD -> {
					pos++;
					List<Directive.Arg> args = new ArrayList<>();
					while (pos < tokens.size() && tokens.get(pos).kind() == Lexer.Kind.WORD) {
						Lexer.Token a = tokens.get(pos++);
						args.add(new Directive.Arg(a.text(), a.quoted()));
					}
					if (pos >= tokens.size()) {
						throw error(t.line(), "unexpected end of file, expecting \";\" or \"}\" after \"" + t.text() + "\"");
					}
					Lexer.Token end = tokens.get(pos++);
					if (end.kind() == Lexer.Kind.SEMICOLON) {
						Directive d = new Directive(t.text(), args, t.line(), currentFile, null);
						d.parent = parent;
						parent.children.add(d);
					} else if (end.kind() == Lexer.Kind.LBRACE) {
						Directive d = new Directive(t.text(), args, t.line(), currentFile, new ArrayList<>());
						d.parent = parent;
						parent.children.add(d);
						if (t.text().endsWith("lua_block") || t.text().equals("lua_block")) {
							skipBalanced();
						} else {
							parseBlock(d, nesting + 1);
						}
					} else {
						throw error(end.line(), "unexpected \"}\"");
					}
				}
			}
		}
		if (nesting > 0) {
			throw error(tokens.isEmpty() ? 1 : tokens.get(tokens.size() - 1).line(), "unexpected end of file, expecting \"}\"");
		}
	}

	/** OpenResty's *_by_lua_block holds Lua, not directives: skip to its matching brace. */
	private void skipBalanced() {
		int depth = 1;
		while (pos < tokens.size() && depth > 0) {
			Lexer.Kind k = tokens.get(pos++).kind();
			if (k == Lexer.Kind.LBRACE) {
				depth++;
			} else if (k == Lexer.Kind.RBRACE) {
				depth--;
			}
		}
		if (depth > 0) {
			throw error(tokens.get(tokens.size() - 1).line(), "unexpected end of file inside a Lua block");
		}
	}

	private void spliceIncludes(Directive block, Path from, List<Path> chain, int depth) {
		List<Directive> out = new ArrayList<>();
		for (Directive d : block.children) {
			if (d.name.equals("include") && !d.isBlock() && d.args.size() == 1) {
				String pattern = d.args.get(0).text();
				if (pattern.contains("$")) {
					out.add(d);
					continue;
				}
				List<Path> matches = resolve(pattern, from);
				if (matches.isEmpty()) {
					unresolvedIncludes.add(d.file + ":" + d.line + ": include " + pattern + " matched no file");
				}
				if (depth + 1 > MAX_INCLUDE_DEPTH) {
					throw new ConfigException(d.file + ":" + d.line + ": includes nested more than " + MAX_INCLUDE_DEPTH + " deep");
				}
				for (Path match : matches) {
					Directive included = parseFile(match, chain, depth + 1);
					for (Directive child : included.children) {
						child.parent = block;
						out.add(child);
					}
				}
			} else {
				if (d.isBlock()) {
					spliceIncludes(d, from, chain, depth);
				}
				out.add(d);
			}
		}
		block.children.clear();
		block.children.addAll(out);
	}

	/**
	 * Resolve an include pattern against the configuration prefix, then the including file's directory.
	 * The pattern is taken apart by hand: it comes from a file we do not trust, and characters such as
	 * {@code *} or {@code :} are not legal in a path on every platform.
	 */
	List<Path> resolve(String pattern, Path from) {
		List<String> components = new ArrayList<>();
		for (String c : pattern.split("/")) {
			if (!c.isEmpty() && !c.equals(".")) {
				components.add(c);
			}
		}
		List<Path> bases = new ArrayList<>();
		if (pattern.length() >= 3 && Character.isLetter(pattern.charAt(0)) && pattern.charAt(1) == ':' && pattern.charAt(2) == '/') {
			// A Windows drive path (nginx for Windows): the drive is the base, not a component.
			try {
				bases.add(Path.of(pattern.substring(0, 3)));
				components.remove(0);
			} catch (java.nio.file.InvalidPathException e) {
				return List.of();
			}
		} else if (pattern.startsWith("/")) {
			Path root = Path.of("/").toAbsolutePath().getRoot();
			bases.add(root == null ? Path.of("/") : root);
		} else {
			bases.add(prefix.toAbsolutePath());
			Path sibling = from.toAbsolutePath().getParent();
			if (sibling != null && !sibling.equals(prefix.toAbsolutePath())) {
				bases.add(sibling);
			}
		}
		for (Path base : bases) {
			List<Path> found = expand(base, components);
			if (!found.isEmpty()) {
				return found;
			}
		}
		return List.of();
	}

	/** Walk the components from base, expanding {@code *}, {@code ?} and {@code [...]} in any of them. */
	private static List<Path> expand(Path base, List<String> components) {
		List<Path> current = new ArrayList<>();
		current.add(base);
		for (String name : components) {
			List<Path> next = new ArrayList<>();
			boolean glob = name.contains("*") || name.contains("?") || name.contains("[");
			for (Path dir : current) {
				if (!glob) {
					try {
						Path candidate = dir.resolve(name).normalize();
						if (Files.exists(candidate)) {
							next.add(candidate);
						}
					} catch (java.nio.file.InvalidPathException e) {
						// Not a legal name on this platform, so no such file.
					}
					continue;
				}
				if (!Files.isDirectory(dir)) {
					continue;
				}
				try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, name)) {
					List<Path> hits = new ArrayList<>();
					stream.forEach(hits::add);
					hits.sort(null);
					next.addAll(hits);
				} catch (IOException | java.util.regex.PatternSyntaxException | java.nio.file.InvalidPathException e) {
					// An unreadable directory or a malformed glob contributes no files.
				}
			}
			current = next;
		}
		Set<Path> seen = new HashSet<>();
		List<Path> files = new ArrayList<>();
		for (Path p : current) {
			if (Files.isRegularFile(p) && seen.add(p)) {
				files.add(p);
			}
		}
		return files;
	}
}
