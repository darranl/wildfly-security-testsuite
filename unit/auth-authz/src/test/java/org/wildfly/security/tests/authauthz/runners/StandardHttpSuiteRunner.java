/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static org.wildfly.security.tests.common.authauthz.deployment.HelloWorldServlet.PRINCIPAL_HEADER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFilter;

/**
 * A runner for standard HTTP authentication against the configured {@code SecurityRealm}.
 *
 * By "Standard" this runner handles standard success / failure scenarios based on good
 * and bad usernames / passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class StandardHttpSuiteRunner extends AbstractHttpSuiteRunner {

    @TestFactory
    Stream<DynamicTest> dynamicHttpTests() {
        // By the time this is called startServer() will have been called in our parent
        // so we don't need the static method calls, instead we get get the policy info from
        // our parent.
        System.out.println("StandardHttpSuiteRunner->dynamicHttpTests");
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<HttpAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms();

        TestFilter testFilter = TestFilter.getInstance();

        String realmType = AbstractAuthenticationSuite.realmType();
        supportedMechnisms.forEach(s -> {
            if (testFilter.shouldRunTest(s, "Success")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpSuccess(%s)", realmType, s), () -> testHttpSuccess(s)));
            }

            if (testFilter.shouldRunTest(s, "BadUsername")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBadUsername(%s)", realmType, s),
                                () -> testHttpBadUsername(s)));
            }

            if (testFilter.shouldRunTest(s, "BadPassword")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBadPassword(%s)", realmType, s),
                                () -> testHttpBadPassword(s)));
            }
        });

        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    private static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode(final int expected) {
        return r -> {
            assertEquals(expected, r.statusCode(), "Status Code");
            return r;
        };
    }

    private static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyNoChallenge() {
        return r -> {
            assertFalse(r.headers().firstValue(WWW_AUTHENTICATE).isPresent(), "Authentication Challenge Unexpected");
            return r;
        };
    }

    private static <T> Function<HttpResponse<T>, HttpResponse<T>> verifyPrincipal(final String expected) {
        return r -> {
            Optional<String> principalHeader = r.headers().firstValue(PRINCIPAL_HEADER);
            assertTrue(principalHeader.isPresent(), "Principal Header Required");
            assertEquals(expected, principalHeader.get(), "Expected Principal");
            return r;
        };
    }

    public void testHttpSuccess(final HttpAuthenticationMechanism mechanism) throws Exception {
        HttpClient httpClient = HttpClient.newHttpClient();
        // Call Unsecured Path to verify accessible
        HttpRequest request = HttpRequest.newBuilder(toURI(mechanism, false)).build();

        // Test Requirements:
        // - Response is HTTP 200
        // - No challenge header
        // - Principal is anonymous

        httpClient.sendAsync(request, BodyHandlers.discarding())
            .thenApply(verifyStatusCode(200))
            .thenApply(verifyNoChallenge())
            .thenApply(verifyPrincipal(NULL))
            .join();

        // Call secured path and verify that the expected challenge was returned (as applicable)

        // Generate a response to the challenge

        // Call deployment again with the challenge and verify success.

    }

    public void testHttpBadUsername(final HttpAuthenticationMechanism mechanism) {
        System.out.printf("testHttpBadUsername(%s)\n", mechanism);
    }

    public void testHttpBadPassword(final HttpAuthenticationMechanism mechanism) {
        System.out.printf("testHttpBadPassword(%s)\n", mechanism);
    }
}
