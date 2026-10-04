package io.github.sriharifortitude.nginxwarden;

/** Entry point: {@code java -jar nginxwarden.jar scan nginx.conf}. */
public final class Main {

	private Main() {
	}

	public static void main(String[] args) {
		System.exit(Cli.run(args, Cli.utf8(System.out), Cli.utf8(System.err)));
	}
}
