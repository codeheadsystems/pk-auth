plugins {
    id("pkauth.java-conventions")
    `java-library`
}

java {
    withJavadocJar()
    withSourcesJar()
}

tasks.withType<JavaCompile>().configureEach {
    // Library modules are held to a stricter compile bar than build-logic itself.
    options.compilerArgs.add("-Werror")
}

tasks.named<JavaCompile>("compileJava") {
    // Several library dependencies (Micrometer, Nimbus, JDBI, the AWS SDK, ...) are automatic
    // modules. javac's `requires-automatic` lints would fire for every module-info that names one,
    // and -Werror would make that fatal, so silence just those two lints for main compilation.
    options.compilerArgs.addAll(
        listOf("-Xlint:-requires-automatic", "-Xlint:-requires-transitive-automatic"),
    )
}

tasks.named<Jar>("jar") {
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
        )
    }
}
