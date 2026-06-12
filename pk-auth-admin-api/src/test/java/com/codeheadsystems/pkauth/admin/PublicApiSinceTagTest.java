// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.admin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Mechanical {@code @since} gate (CONTRIBUTING.md §7): every public top-level type in
 * pk-auth-admin-api must carry a class-level {@code @since} Javadoc tag. When this fails, add
 * {@code @since <version>} to the type's class Javadoc.
 */
class PublicApiSinceTagTest {

  private static final Path SOURCE_ROOT = Path.of("src/main/java/com/codeheadsystems/pkauth/admin");

  private static final Pattern TYPE_DECL =
      Pattern.compile(
          "^(public\\s+(?:final\\s+|abstract\\s+|sealed\\s+|non-sealed\\s+)*)"
              + "(class|interface|record|enum)\\s+(\\w+)",
          Pattern.MULTILINE);

  @Test
  void everyPublicTypeHasSinceTag() throws IOException {
    assertThat(SOURCE_ROOT).as("source root must exist").exists();
    List<String> violations = new ArrayList<>();
    try (Stream<Path> files = Files.walk(SOURCE_ROOT)) {
      files
          .filter(p -> p.toString().endsWith(".java"))
          .filter(p -> !p.getFileName().toString().equals("package-info.java"))
          .filter(p -> !p.getFileName().toString().equals("module-info.java"))
          .forEach(p -> checkFile(p, violations));
    }
    assertThat(violations).as("public types missing a class-level @since tag").isEmpty();
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
      return;
    }
    String javadoc = precedingJavadoc(src, m.start());
    if (javadoc == null || !javadoc.contains("@since")) {
      violations.add(file.getFileName() + " (" + m.group(3) + ")");
    }
  }

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
    String between = head.substring(close + 2);
    if (between.matches("(?s).*\\b(class|interface|record|enum)\\b.*")) {
      return null;
    }
    return head.substring(open, close + 2);
  }
}
