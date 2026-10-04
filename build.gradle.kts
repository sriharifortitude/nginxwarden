plugins {
	java
}

group = "io.github.sriharifortitude"
version = "0.1.0"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

repositories {
	mavenCentral()
}

// No runtime dependencies: the jar is the whole program.
dependencies {
	testImplementation(platform("org.junit:junit-bom:5.11.4"))
	testImplementation("org.junit.jupiter:junit-jupiter")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
	useJUnitPlatform()
}

tasks.withType<JavaCompile> {
	options.encoding = "UTF-8"
	options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.jar {
	archiveFileName = "nginxwarden.jar"
	manifest {
		attributes["Main-Class"] = "io.github.sriharifortitude.nginxwarden.Main"
	}
}
