/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.common.authauthz.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.tests.common.authauthz.deployment.HelloWorldServlet.PRINCIPAL_HEADER;

import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;

/**
 * Common verification functionality for use with {@code HttpClient} when testing
 * authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpClientAuthenticationCommon {

    static final String AUTHORIZATION = "Authorization";
    static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    public static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyMechanismChallenge(HttpAuthenticationMechanism testMechanism, Consumer<String> challengeConsumer) {
        return r -> {
            List<String> authenticateHeaders = r.headers().allValues(WWW_AUTHENTICATE);
            assertEquals(1, authenticateHeaders.size(), "Single WWW_AUTHENTICATE expected.");
            String header = authenticateHeaders.get(0);
            int space = header.indexOf(' ');
            assertEquals(testMechanism.getChallenge(), header.substring(0, space), "Mechanism Name");
            challengeConsumer.accept(header.substring(space + 1));

            return r;
        };
    }

    public static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyNoChallenge() {
        return r -> {
            assertFalse(r.headers().firstValue(WWW_AUTHENTICATE).isPresent(), "Authentication Challenge Unexpected");
            return r;
        };
    }

    public static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyMechanismChallenge(HttpAuthenticationMechanism testMechanism) {
        return verifyMechanismChallenge(testMechanism, s -> {});
    }

    public static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode(final int expected) {
        return r -> {
            assertEquals(expected, r.statusCode(), "Status Code");
           return r;
        };
    }

    public static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyPrincipal(final String expected) {
        return r -> {
            Optional<String> principalHeader = r.headers().firstValue(PRINCIPAL_HEADER);
            assertTrue(principalHeader.isPresent(), "Principal Header Required");
            assertEquals(expected, principalHeader.get(), "Expected Principal");
            return r;
        };
    }

}
