// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.lifecycle;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fans out a "delete this user" command across every registered {@link UserDeletionListener}.
 * Adapter modules ({@code pk-auth-spring-boot-starter}, {@code pk-auth-dropwizard}, {@code
 * pk-auth-micronaut}) collect every listener bean and pass them in.
 *
 * <p>Semantics are sequential, isolated, and best-effort. Listeners are invoked in the iteration
 * order of the supplied collection, each in its own scope. A listener that throws is logged via a
 * structured {@code pkauth.user.deletion} event and the service proceeds with the next listener.
 * The returned {@link UserDeletionResult} reports successes and failures by name.
 *
 * <p>Listeners do not share a transaction, because the persistence SPIs span multiple datasources
 * (JDBC pool, DynamoDB client, in-memory collections) with no shared transactional substrate. See
 * ADR 0016.
 *
 * <p>Failed listeners are non-fatal and the service does not throw. A partial cleanup with an audit
 * trail is preferable to a hard failure that leaves the user in a worse half-state. Operators
 * should watch the structured log for non-zero {@code failed} counts and retry, since {@link
 * UserDeletionListener} implementations are required to be idempotent.
 *
 * @since 1.1.0
 */
public final class UserDeletionService {

  private static final Logger LOG = LoggerFactory.getLogger(UserDeletionService.class);

  private final List<UserDeletionListener> listeners;

  /**
   * Constructs the service with the supplied listeners. Iteration order of the collection is the
   * order in which listeners run; callers pass a {@code List} (or other ordered collection) when
   * order matters. The collection is copied defensively.
   */
  public UserDeletionService(Collection<UserDeletionListener> listeners) {
    Objects.requireNonNull(listeners, "listeners");
    this.listeners = List.copyOf(listeners);
  }

  /**
   * Runs every listener for the supplied user. Failures from individual listeners are logged and
   * counted, then the service continues. The returned {@link UserDeletionResult} summarises the
   * outcome.
   */
  public UserDeletionResult deleteUser(UserHandle userHandle) {
    Objects.requireNonNull(userHandle, "userHandle");
    String userHandleB64u = Base64Url.encode(userHandle.value());
    int succeeded = 0;
    List<String> failedNames = new ArrayList<>();
    for (UserDeletionListener listener : listeners) {
      String name = listener.name();
      try {
        listener.onUserDeleted(userHandle);
        succeeded++;
        LOG.info(
            "pkauth.user.deletion listener={} user_handle_b64={} outcome=ok", name, userHandleB64u);
      } catch (RuntimeException e) {
        failedNames.add(name);
        LOG.error(
            "pkauth.user.deletion listener={} user_handle_b64={} outcome=failed cause={}",
            name,
            userHandleB64u,
            e.toString(),
            e);
      }
    }
    return new UserDeletionResult(succeeded, failedNames.size(), failedNames);
  }
}
