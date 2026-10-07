// SPDX-License-Identifier: MIT

/**
 * Service-provider interfaces implemented by persistence, time, and policy adapters.
 *
 * <p>Exception contract: every method on every SPI in this package promises that an operational
 * failure of the underlying backend (DB connection drop, DynamoDB throttle, etc.) surfaces as a
 * {@link com.codeheadsystems.pkauth.spi.PkAuthPersistenceException}. Implementers should wrap their
 * backend's native exception in that type. Adapters install one framework exception handler that
 * maps it to a stable {@code 503} response so adopters get a consistent error shape instead of
 * framework-default 500 HTML.
 *
 * <p>{@link IllegalArgumentException} is reserved for caller-side programming errors (null or
 * malformed inputs); adapters typically map those to {@code 400}. Anything else that escapes is
 * treated as an unhandled exception and surfaces as the framework's default 500.
 */
@org.jspecify.annotations.NullMarked
package com.codeheadsystems.pkauth.spi;
