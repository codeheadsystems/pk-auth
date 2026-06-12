// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.micronaut;

import static org.assertj.core.api.Assertions.assertThat;

import io.micronaut.core.annotation.Introspected;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Asserts that {@link PkAuthIntrospections} lists every record (and sealed-interface variant) that
 * ships in the pk-auth wire packages ({@code com.codeheadsystems.pkauth.api} and {@code
 * com.codeheadsystems.pkauth.admin}). A new wire type that Micronaut never sees will deserialize as
 * a {@code 400 Bad Request} at runtime — this build-time guard catches the omission instead.
 *
 * @since 0.9.1
 */
class PkAuthIntrospectionsCoverageTest {

  private static final List<String> SCANNED_PACKAGES =
      List.of("com.codeheadsystems.pkauth.api", "com.codeheadsystems.pkauth.admin");

  /**
   * Records that are intentionally NOT in the introspection sweep — server-side configuration or
   * helper-internal records that never cross the Micronaut serialization boundary.
   */
  private static final Set<String> EXEMPT =
      Set.of(
          "com.codeheadsystems.pkauth.admin.AdminSafetyConfig",
          // DI / config records consumed only by hand-written wiring code.
          "com.codeheadsystems.pkauth.admin.DefaultAdminService$Dependencies",
          "com.codeheadsystems.pkauth.admin.DefaultAdminService$Config",
          // Internal mapper return shapes — the adapter unwraps these into framework
          // response objects, the records themselves are never JSON-serialized.
          "com.codeheadsystems.pkauth.api.CeremonyWireMapper$CeremonyResponse",
          "com.codeheadsystems.pkauth.admin.AdminResponseMapper$AdminResponse",
          // start*-ceremony result sums — the controller serializes the Started variant's wrapped
          // response (already introspected) or maps RateLimited to the rate_limited body; the
          // result records themselves never cross the serialization boundary.
          "com.codeheadsystems.pkauth.api.StartRegistrationResult$Started",
          "com.codeheadsystems.pkauth.api.StartRegistrationResult$RateLimited",
          "com.codeheadsystems.pkauth.api.StartAuthenticationResult$Started",
          "com.codeheadsystems.pkauth.api.StartAuthenticationResult$RateLimited");

  @Test
  void everyWireRecordIsIntrospected() throws Exception {
    Set<Class<?>> registered = registeredClasses();
    Set<Class<?>> wireRecords = new LinkedHashSet<>();
    for (String pkg : SCANNED_PACKAGES) {
      wireRecords.addAll(recordsIn(pkg));
    }

    Set<Class<?>> missing = new LinkedHashSet<>();
    for (Class<?> rec : wireRecords) {
      if (EXEMPT.contains(rec.getName())) continue;
      if (!registered.contains(rec)) missing.add(rec);
    }

    assertThat(missing)
        .as(
            "PkAuthIntrospections is missing @Introspected entries for the following wire records;"
                + " add them to the classes={} list or to the EXEMPT set with a reason.")
        .isEmpty();
  }

  private static Set<Class<?>> registeredClasses() {
    Introspected ann = PkAuthIntrospections.class.getAnnotation(Introspected.class);
    Class<?>[] classes = ann == null ? new Class<?>[0] : ann.classes();
    return new LinkedHashSet<>(Arrays.asList(classes));
  }

  private static Set<Class<?>> recordsIn(String pkg) throws IOException {
    Set<Class<?>> out = new LinkedHashSet<>();
    String resourceName = pkg.replace('.', '/');
    var urls = Thread.currentThread().getContextClassLoader().getResources(resourceName);
    while (urls.hasMoreElements()) {
      URI uri = toUri(urls.nextElement());
      if ("jar".equals(uri.getScheme())) {
        try (FileSystem fs = FileSystems.newFileSystem(uri, Collections.emptyMap())) {
          collectFrom(fs.getPath(resourceName), pkg, out);
        }
      } else {
        collectFrom(Path.of(uri), pkg, out);
      }
    }
    return out;
  }

  private static URI toUri(java.net.URL url) {
    try {
      return url.toURI();
    } catch (java.net.URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void collectFrom(Path dir, String pkg, Set<Class<?>> out) throws IOException {
    if (!Files.isDirectory(dir)) return;
    try (Stream<Path> stream = Files.list(dir)) {
      for (Path p : (Iterable<Path>) stream::iterator) {
        String name = p.getFileName().toString();
        if (!name.endsWith(".class")) continue;
        if (name.equals("package-info.class") || name.equals("module-info.class")) continue;
        String simple = name.substring(0, name.length() - ".class".length());
        String fqcn = pkg + "." + simple;
        try {
          Class<?> c = Class.forName(fqcn, false, Thread.currentThread().getContextClassLoader());
          if (!c.isRecord()) continue;
          if (java.lang.reflect.Modifier.isPublic(c.getModifiers())) {
            out.add(c);
          }
        } catch (ClassNotFoundException | NoClassDefFoundError ignored) {
          // skip unloadable inner classes
        }
      }
    }
  }
}
