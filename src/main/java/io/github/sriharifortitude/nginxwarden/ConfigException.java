package io.github.sriharifortitude.nginxwarden;

/** A file that is not a valid nginx configuration, or cannot be read. */
final class ConfigException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	ConfigException(String message) {
		super(message);
	}
}
