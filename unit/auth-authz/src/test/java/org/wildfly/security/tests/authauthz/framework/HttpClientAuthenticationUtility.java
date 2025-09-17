/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.framework;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.function.Function;

import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;

/**
 * Utility used by tests to verify and handle client side authentication.
 *
 * The implementation of this utility can be considered stateful, after being
 * used to verify a challenge this utility can then generate a response to that
 * challenge. Additionally this utility should also be usable for subsequent
 * requests following the original challenge and any subsequent responses taking
 * into account additional state such as client nonces where necessary.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpClientAuthenticationUtility {

    /**
     * Return the {@code Function} that can be used to verify that the server
     * correctly challenged the request.
     *
     * This is only to verify the first challenge for a client that has not
     * previously authenticated.
     *
     * This verification may capture information from the challenge such as
     * Cookies, redirect URLs or challenge headers which may be required to
     * subsequently authenticate.
     *
     * @param <T> the response body type.
     * @return the {@code Function} that can be used to verify that the server
     * correctly challenged the request.
     */
    <T> Function<HttpResponse<T>, HttpResponse<T>> verifyChallenge();

    /**
     * Create the authentication {@code HttpRequest} to access the specified resource.
     *
     * The provided {@code URI} is for guidance only, the verified challenge may have
     * redirected to a different URI to authenticate.
     *
     * For header based authentication where we do not rely on an authenticated session
     * the username and password may be cached for subsequent requests.
     *
     * For mechanisms that rely on responding to a challenge this method may depend upon
     * that previously captured data when verifying a challenge.
     *
     * @param resource the target resource.
     * @param username the username to use for authentication.
     * @param password the password that corresponds to the username.
     * @return
     */
    public HttpRequest createAuthenticationRequest(final URI resource, final String username, final String password);

    /**
     * Verify the outcome of the authentication request.
     *
     * If the request results in an authenticated session the session information
     * should be captured for subsequent requests.
     *
     * @param <T> the response body type.
     * @param expectSuccess was this authentication expected to succeed.
     * @return a {@code Function} to verify the result of the authentcation.
     */
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyAuthentication(boolean expectSuccess);

    /**
     * Create a {@code HttpRequest} to access the resource.
     *
     * If authentication has already been completed by the instance of this
     * {@code HttpClientAuthenticationUtility} then this new request should also
     * be authenticated. This could be by sending suitable authorization headers or
     * where appropriate maintaining a HTTP session.
     *
     * @param resource
     * @return
     */
    public HttpRequest createRequest(final URI resource);

    public static Builder builder(HttpAuthenticationMechanism forMechanism) {
        return new Builder(forMechanism);
    }

    public static class Builder {

        final HttpAuthenticationMechanism mechanism;

        private Builder(final HttpAuthenticationMechanism mechanism) {
            this.mechanism = mechanism;
        }

        public HttpClientAuthenticationUtility build() {
            switch (mechanism) {
                case BASIC:
                    return new HttpBasicClientAuthenticationUtility();
                case DIGEST_MD5:
                    return new HttpDigestClientAuthenticationUtility();
                case FORM:
                    return new HttpFormClientAuthenticationUtility();
                default:
                    return null;
            }
        }

    }
}
