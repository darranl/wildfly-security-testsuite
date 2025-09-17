/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;


import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyNoChallenge;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyPrincipal;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyStatusCode;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationUtility;
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

    // TODO - Which of the following do we need to be dynamic based on the realm under test?
    private final String goodUsername = "user1";
    private final String goodPassword = "password1";
    private final String badUsername = "bob";
    private final String badPassword = "passwordx";

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

    private static HttpClient newHttpClient() {
        // We create a new client for each test scenario for a clean cookie manager.
        CookieManager cookieManager = new CookieManager();
        return HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .build();
    }

    public void testHttpSuccess(final HttpAuthenticationMechanism mechanism) throws Exception {
        System.out.println("~~ Set Up");
        HttpClient httpClient = newHttpClient();

        HttpClientAuthenticationUtility authUtility = HttpClientAuthenticationUtility.builder(mechanism)
            .build();

        // Call Unsecured Path to verify accessible
        HttpRequest request = authUtility.createRequest(toURI(mechanism, false));

        // Test Requirements:
        // - Response is HTTP 200
        // - No challenge header
        // - Principal is 'null'
        System.out.println("~~ Insecure Request");
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(verifyStatusCode(200))
            .thenApply(verifyNoChallenge())
            .thenApply(verifyPrincipal(NULL))
            .join();

        // Call secured path and verify that the expected challenge was returned (as applicable)
        System.out.println("~~ First Challenge");
        URI securedResource = toURI(mechanism, true);
        request = HttpRequest.newBuilder(securedResource).build();
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyChallenge())
            .join();

        // Generate a response to the challenge
        System.out.println("~~ Respond to Challenge");
        request = authUtility.createAuthenticationRequest(securedResource, goodUsername, goodPassword);
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyAuthentication(true))
            .join();

        // Call deployment again with the challenge and verify success.
        System.out.println("~~ Second call");
        request = authUtility.createRequest(securedResource);
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyAuthentication(true))
            .join();
    }

    public void testHttpBadUsername(final HttpAuthenticationMechanism mechanism) throws Exception {
        HttpClient httpClient = newHttpClient();

        HttpClientAuthenticationUtility authUtility = HttpClientAuthenticationUtility.builder(mechanism)
            .build();

        // Call Unsecured Path to verify accessible
        HttpRequest request = authUtility.createRequest(toURI(mechanism, false));

        // Test Requirements:
        // - Response is HTTP 200
        // - No challenge header
        // - Principal is 'null'
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(verifyStatusCode(200))
            .thenApply(verifyNoChallenge())
            .thenApply(verifyPrincipal(NULL))
            .join();

        // Call secured path and verify that the expected challenge was returned (as applicable)
        URI securedResource = toURI(mechanism, true);
        request = HttpRequest.newBuilder(securedResource).build();
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyChallenge())
            .join();

        // Generate a response to the challenge
        request = authUtility.createAuthenticationRequest(securedResource, badUsername, goodPassword);
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyAuthentication(false))
            .join();
    }

    public void testHttpBadPassword(final HttpAuthenticationMechanism mechanism) throws Exception {
        HttpClient httpClient = newHttpClient();

        HttpClientAuthenticationUtility authUtility = HttpClientAuthenticationUtility.builder(mechanism)
            .build();

        // Call Unsecured Path to verify accessible
        HttpRequest request = authUtility.createRequest(toURI(mechanism, false));

        // Test Requirements:
        // - Response is HTTP 200
        // - No challenge header
        // - Principal is 'null'
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(verifyStatusCode(200))
            .thenApply(verifyNoChallenge())
            .thenApply(verifyPrincipal(NULL))
            .join();

        // Call secured path and verify that the expected challenge was returned (as applicable)
        URI securedResource = toURI(mechanism, true);
        request = HttpRequest.newBuilder(securedResource).build();
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyChallenge())
            .join();

        // Generate a response to the challenge
        request = authUtility.createAuthenticationRequest(securedResource, goodUsername, badPassword);
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyAuthentication(false))
            .join();
    }
}
