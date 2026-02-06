/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.common.authauthz.http;

import static org.wildfly.security.tests.common.authauthz.http.HttpClientAuthenticationCommon.verifyNoChallenge;
import static org.wildfly.security.tests.common.authauthz.http.HttpClientAuthenticationCommon.verifyPrincipal;
import static org.wildfly.security.tests.common.authauthz.http.HttpClientAuthenticationCommon.verifyStatusCode;

import java.net.CookieManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpClient.Version;
import java.net.http.HttpResponse.BodyHandlers;

import org.wildfly.common.function.ExceptionBiFunction;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;

/**
 * A common test utility for HTTP invocations.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HttpTestClient {

    // TODO - Which of the following do we need to be dynamic based on the realm under test?
    private static final String goodUsername = "user1";
    private static final String goodPassword = "password1";
    private static final String badUsername = "bob";
    private static final String badPassword = "passwordx";

    private static final String NULL = "null";
    private static final int HTTP_OK = 200;

    private final ExceptionBiFunction<HttpAuthenticationMechanism, Boolean, URI, URISyntaxException> toUri;

    HttpTestClient(ExceptionBiFunction<HttpAuthenticationMechanism, Boolean, URI, URISyntaxException> toUri) {
        this.toUri = toUri;
    }

    private static HttpClient newHttpClient() {
        // We create a new client for each test scenario for a clean cookie manager.
        CookieManager cookieManager = new CookieManager();
        return HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .version(Version.HTTP_1_1) // Make Network Traces Easier To Read
            .build();
    }

    public void testHttpSuccess(final HttpAuthenticationMechanism mechanism) throws Exception {
        testHttpSuccess(mechanism, goodUsername, goodPassword);
    }

    public void testHttpSuccess(final HttpAuthenticationMechanism mechanism, final String username, final String password)
            throws Exception {

        System.out.println("~~ Set Up");
        HttpClient httpClient = newHttpClient();

        HttpClientAuthenticationUtility authUtility = HttpClientAuthenticationUtility.builder(mechanism)
            .build();

        // Call Unsecured Path to verify accessible
        HttpRequest request = authUtility.createRequest(toUri.apply(mechanism, false));

        // Test Requirements:
        // - Response is HTTP 200
        // - No challenge header
        // - Principal is 'null'
        System.out.println("~~ Insecure Request");
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(verifyStatusCode(HTTP_OK))
            .thenApply(verifyNoChallenge())
            .thenApply(verifyPrincipal(NULL))
            .join();

        // Call secured path and verify that the expected challenge was returned (as applicable)
        System.out.println("~~ First Challenge");
        URI securedResource = toUri.apply(mechanism, true);
        request = HttpRequest.newBuilder(securedResource).build();
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyChallenge())
            .join();

        // Generate a response to the challenge
        System.out.println("~~ Respond to Challenge");
        request = authUtility.createAuthenticationRequest(securedResource, username, password);
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
        HttpRequest request = authUtility.createRequest(toUri.apply(mechanism, false));

        // Test Requirements:
        // - Response is HTTP 200
        // - No challenge header
        // - Principal is 'null'
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(verifyStatusCode(HTTP_OK))
            .thenApply(verifyNoChallenge())
            .thenApply(verifyPrincipal(NULL))
            .join();

        // Call secured path and verify that the expected challenge was returned (as applicable)
        URI securedResource = toUri.apply(mechanism, true);
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
        testHttpBadPassword(mechanism, goodUsername, badPassword);
    }

    public void testHttpBadPassword(final HttpAuthenticationMechanism mechanism, final String username, final String password)
            throws Exception {

        HttpClient httpClient = newHttpClient();

        HttpClientAuthenticationUtility authUtility = HttpClientAuthenticationUtility.builder(mechanism)
            .build();

        // Call Unsecured Path to verify accessible
        HttpRequest request = authUtility.createRequest(toUri.apply(mechanism, false));

        // Test Requirements:
        // - Response is HTTP 200
        // - No challenge header
        // - Principal is 'null'
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(verifyStatusCode(HTTP_OK))
            .thenApply(verifyNoChallenge())
            .thenApply(verifyPrincipal(NULL))
            .join();

        // Call secured path and verify that the expected challenge was returned (as applicable)
        URI securedResource = toUri.apply(mechanism, true);
        request = HttpRequest.newBuilder(securedResource).build();
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyChallenge())
            .join();

        // Generate a response to the challenge
        request = authUtility.createAuthenticationRequest(securedResource, username, password);
        httpClient.sendAsync(request, BodyHandlers.ofString())
            .thenApply(authUtility.verifyAuthentication(false))
            .join();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private ExceptionBiFunction<HttpAuthenticationMechanism, Boolean, URI, URISyntaxException> toUri = null;;

        public Builder withToUri(ExceptionBiFunction<HttpAuthenticationMechanism, Boolean, URI, URISyntaxException> toUri) {
            this.toUri = toUri;

            return this;
        }
        public HttpTestClient build() {
            return new HttpTestClient(toUri);
        }

    }

}
