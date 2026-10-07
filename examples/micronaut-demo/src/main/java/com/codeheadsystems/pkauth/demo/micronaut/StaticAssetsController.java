// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.demo.micronaut;

import io.micronaut.core.io.IOUtils;
import io.micronaut.core.io.ResourceResolver;
import io.micronaut.core.io.scan.ClassPathResourceLoader;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import jakarta.inject.Inject;
import java.io.BufferedReader;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Serves the demo's single-page HTML, the shared SDK ESM bundle, and the demo glue script from
 * {@code src/main/resources/public/}. The YAML {@code micronaut.router.static-resources} block is
 * the idiomatic Micronaut approach for this, but it does not reliably pick up the classpath path in
 * this demo's runtime, so three explicit handlers serve them instead. This keeps the demo free of
 * Micronaut features beyond {@code @Controller}.
 */
@Controller("/")
public final class StaticAssetsController {

  private final ClassPathResourceLoader loader;

  @Inject
  public StaticAssetsController(ResourceResolver resourceResolver) {
    this.loader =
        resourceResolver
            .getLoader(ClassPathResourceLoader.class)
            .orElseThrow(() -> new IllegalStateException("classpath resource loader not present"));
  }

  @Get
  @Produces(MediaType.TEXT_HTML)
  public HttpResponse<String> index() {
    return readClasspath("public/index.html")
        .map(HttpResponse::ok)
        .orElseGet(HttpResponse::notFound);
  }

  @Get("/index.html")
  @Produces(MediaType.TEXT_HTML)
  public HttpResponse<String> indexHtml() {
    return index();
  }

  @Get("/demo.js")
  @Produces("application/javascript")
  public HttpResponse<String> demoJs() {
    return readClasspath("public/demo.js").map(HttpResponse::ok).orElseGet(HttpResponse::notFound);
  }

  @Get("/passkeys-browser/index.js")
  @Produces("application/javascript")
  public HttpResponse<String> sdk() {
    return readClasspath("public/passkeys-browser/index.js")
        .map(HttpResponse::ok)
        .orElseGet(HttpResponse::notFound);
  }

  private Optional<String> readClasspath(String relative) {
    Optional<URL> url = loader.getResource(relative);
    if (url.isEmpty()) return Optional.empty();
    try {
      // file:/ URLs (running from build/resources/main/) read directly; jar: URLs work via stream.
      if ("file".equals(url.get().getProtocol())) {
        return Optional.of(Files.readString(Paths.get(url.get().toURI()), StandardCharsets.UTF_8));
      }
      try (BufferedReader r =
          new BufferedReader(
              new java.io.InputStreamReader(url.get().openStream(), StandardCharsets.UTF_8))) {
        return Optional.of(IOUtils.readText(r));
      }
    } catch (IOException | java.net.URISyntaxException e) {
      throw new IllegalStateException("Failed to read classpath resource: " + relative, e);
    }
  }
}
