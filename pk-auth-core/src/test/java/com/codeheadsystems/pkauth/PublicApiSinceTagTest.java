// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Mechanical {@code @since} gate (CONTRIBUTING.md §7): every public top-level type in an exported
 * package must carry a class-level {@code @since} Javadoc tag. This stops the convention from
 * silently rotting on the most load-bearing types — when it fails, add {@code @since <version>} to
 * the type's class Javadoc (the in-flight version from {@code gradle.properties}, minus {@code
 * -SNAPSHOT}).
 */
class PublicApiSinceTagTest {

  /** Packages exported by {@code module-info.java}. Keep in sync with the module declaration. */
  private static final Set<String> EXPORTED_PACKAGES =
      Set.of(
          "api",
          "ceremony",
          "config",
          "credential",
          "error",
          "json",
          "lifecycle",
          "metrics",
          "spi");

  private static final Path SOURCE_ROOT = Path.of("src/main/java/com/codeheadsystems/pkauth");

  private static final Pattern TYPE_DECL =
      Pattern.compile(
          "^(public\\s+(?:final\\s+|abstract\\s+|sealed\\s+|non-sealed\\s+)*)"
              + "(class|interface|record|enum)\\s+(\\w+)",
          Pattern.MULTILINE);

  @Test
  void everyExportedPublicTypeHasSinceTag() throws IOException {
    assertThat(SOURCE_ROOT).as("source root must exist").exists();
    List<String> violations = new ArrayList<>();
    try (Stream<Path> files = Files.walk(SOURCE_ROOT)) {
      files
          .filter(p -> p.toString().endsWith(".java"))
          .filter(p -> !p.getFileName().toString().equals("package-info.java"))
          .filter(p -> !p.getFileName().toString().equals("module-info.java"))
          .filter(PublicApiSinceTagTest::inExportedPackage)
          .forEach(p -> checkFile(p, violations));
    }
    assertThat(violations)
        .as("public types in exported packages missing a class-level @since tag")
        .isEmpty();
  }

  private static boolean inExportedPackage(Path file) {
    Path rel = SOURCE_ROOT.relativize(file);
    return rel.getNameCount() >= 2 && EXPORTED_PACKAGES.contains(rel.getName(0).toString());
  }

  private static void checkFile(Path file, List<String> violations) {
    String src;
    try {
      src = Files.readString(file);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    Matcher m = TYPE_DECL.matcher(src);
    if (!m.find()) {
      return; // no public top-level type (e.g. an internal-only helper)
    }
    String javadoc = precedingJavadoc(src, m.start());
    if (javadoc == null || !javadoc.contains("@since")) {
      violations.add(file.getFileName() + " (" + m.group(3) + ")");
    }
  }

  /** Returns the Javadoc block immediately preceding {@code declStart}, or {@code null}. */
  private static String precedingJavadoc(String src, int declStart) {
    String head = src.substring(0, declStart);
    int close = head.lastIndexOf("*/");
    if (close < 0) {
      return null;
    }
    int open = head.lastIndexOf("/**", close);
    if (open < 0) {
      return null;
    }
    // Nothing but annotations / whitespace may sit between the Javadoc and the declaration.
    String between = head.substring(close + 2);
    if (between.matches("(?s).*\\b(class|interface|record|enum)\\b.*")) {
      return null;
    }
    return head.substring(open, close + 2);
  }
}
