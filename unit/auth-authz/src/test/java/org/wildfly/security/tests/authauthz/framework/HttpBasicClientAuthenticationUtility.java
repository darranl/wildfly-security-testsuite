/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.framework;

import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.AUTHORIZATION;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyStatusCode;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyPrincipal;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyNoChallenge;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyMechanismChallenge;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Consumer;
import java.util.function.Function;

import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;

/**
 * An implementation of {@code HttpClientAuthenticationUtility} for HTTP BASIC
 * authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class HttpBasicClientAuthenticationUtility implements HttpClientAuthenticationUtility {

    // TODO does this need to be dynamic?
    private final String expectedRealm = "Elytron Realm";
    // Constants
    private final String realmPattern = "realm=\"%s\"";

    // Cached Data
    private volatile String username = null;
    private volatile String password = null;

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyChallenge() {
        Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(401);
        Consumer<String> challengeConsumer = s -> assertEquals(String.format(realmPattern, expectedRealm), s, "Expected Challenge");

        Function<HttpResponse<T>, HttpResponse<T>> verifyMechanismChallenge = verifyMechanismChallenge(HttpAuthenticationMechanism.BASIC, challengeConsumer);

        return verifyStatusCode.andThen(verifyMechanismChallenge);
    }

    @Override
    public HttpRequest createAuthenticationRequest(final URI resource, final String username, final String password) {
        this.username = username;
        this.password = password;

        // All BASIC auth calls need the username and password so now that we have cached these we can use
        // createRequest(URI);
        return createRequest(resource);
    }

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyAuthentication(boolean expectSuccess) {
        if (expectSuccess) {
            Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(200);
            Function<HttpResponse<T>, HttpResponse<T>> verifyPrincipal = verifyPrincipal(username);

            return verifyStatusCode.andThen(verifyPrincipal);
        } else {
            return verifyChallenge();
        }
    }

    @Override
    public HttpRequest createRequest(final URI resource) {
        return HttpRequest.newBuilder(resource)
            .header(AUTHORIZATION, "Basic " + encodeUsernamePassword())
            .build();
    }

    private String encodeUsernamePassword() {
        return Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

}
