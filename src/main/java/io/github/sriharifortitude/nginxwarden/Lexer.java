package io.github.sriharifortitude.nginxwarden;

import java.util.ArrayList;
import java.util.List;

/**
 * Tokeniser for nginx's configuration syntax, following ngx_conf_read_token:
 * whitespace separates words, {@code ;} {@code {} and {@code }} are tokens of
 * their own (except {@code ${var}}, which is part of a word), {@code #} starts a
 * comment, and a word that opens with a quote reads to the matching quote with
 * backslash escapes.
 */
final class Lexer {

	enum Kind { WORD, SEMICOLON, LBRACE, RBRACE }

	record Token(Kind kind, String text, int line, boolean quoted) {
		static Token of(Kind kind, String text, int line) {
			return new Token(kind, text, line, false);
		}
	}

	private Lexer() {
	}

	static List<Token> lex(String src) {
		List<Token> out = new ArrayList<>();
		int i = 0;
		int line = 1;
		int n = src.length();
		while (i < n) {
			char c = src.charAt(i);
			if (c == '\n') {
				line++;
				i++;
			} else if (Character.isWhitespace(c)) {
				i++;
			} else if (c == '#') {
				while (i < n && src.charAt(i) != '\n') {
					i++;
				}
			} else if (c == ';') {
				out.add(Token.of(Kind.SEMICOLON, ";", line));
				i++;
			} else if (c == '{') {
				out.add(Token.of(Kind.LBRACE, "{", line));
				i++;
			} else if (c == '}') {
				out.add(Token.of(Kind.RBRACE, "}", line));
				i++;
			} else if (c == '"' || c == '\'') {
				int start = line;
				StringBuilder sb = new StringBuilder();
				i++;
				while (true) {
					if (i >= n) {
						throw new ConfigException("line " + start + ": unterminated " + (c == '"' ? "double" : "single") + "-quoted string");
					}
					char d = src.charAt(i);
					if (d == '\\' && i + 1 < n) {
						char e = src.charAt(i + 1);
						switch (e) {
							case '"', '\'', '\\' -> sb.append(e);
							case 't' -> sb.append('\t');
							case 'r' -> sb.append('\r');
							case 'n' -> sb.append('\n');
							default -> sb.append(d).append(e);
						}
						if (e == '\n') {
							line++;
						}
						i += 2;
						continue;
					}
					if (d == c) {
						i++;
						break;
					}
					if (d == '\n') {
						line++;
					}
					sb.append(d);
					i++;
				}
				out.add(new Token(Kind.WORD, sb.toString(), start, true));
			} else {
				int start = i;
				while (i < n) {
					char d = src.charAt(i);
					if (Character.isWhitespace(d) || d == ';' || d == '}') {
						break;
					}
					if (d == '{') {
						break;
					}
					if (d == '$' && i + 1 < n && src.charAt(i + 1) == '{') {
						// ${var}: the braces belong to the word.
						int close = src.indexOf('}', i + 2);
						if (close < 0) {
							throw new ConfigException("line " + line + ": unterminated ${ variable");
						}
						i = close + 1;
						continue;
					}
					i++;
				}
				out.add(Token.of(Kind.WORD, src.substring(start, i), line));
			}
		}
		return out;
	}
}
