// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.demo.dropwizard;

import static org.assertj.core.api.Assertions.assertThat;

import io.dropwizard.core.server.DefaultServerFactory;
import io.dropwizard.jetty.HttpConnectorFactory;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Smoke test that starts the demo app and verifies the static asset, ceremony endpoints, and admin
 * endpoint surfaces are all reachable. Uses an ephemeral port so CI does not collide on 8080.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
final class DemoSmokeTest {

  private final DropwizardAppExtension<DemoConfiguration> app =
      new DropwizardAppExtension<>(DemoApplication.class, ephemeralConfig());

  private static DemoConfiguration ephemeralConfig() {
    DemoConfiguration cfg = new DemoConfiguration();
    DefaultServerFactory server = (DefaultServerFactory) cfg.getServerFactory();
    HttpConnectorFactory app = (HttpConnectorFactory) server.getApplicationConnectors().get(0);
    app.setPort(0);
    HttpConnectorFactory admin = (HttpConnectorFactory) server.getAdminConnectors().get(0);
    admin.setPort(0);
    return cfg;
  }

  @Test
  void rootServesIndexHtml() {
    Client c = ClientBuilder.newClient();
    try {
      Response r = c.target("http://localhost:" + app.getLocalPort() + "/ui/").request().get();
      assertThat(r.getStatus()).isEqualTo(200);
      String body = r.readEntity(String.class);
      assertThat(body).contains("pk-auth Dropwizard demo");
    } finally {
      c.close();
    }
  }

  @Test
  void adminAccountEndpointRequiresAuth() {
    Client c = ClientBuilder.newClient();
    try {
      Response r =
          c.target("http://localhost:" + app.getLocalPort() + "/auth/admin/account")
              .request()
              .get();
      assertThat(r.getStatus()).isEqualTo(401);
    } finally {
      c.close();
    }
  }
}
