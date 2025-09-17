/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.framework;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyNoChallenge;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyPrincipal;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyStatusCode;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

/**
 * An implementation of {@code HttpClientAuthenticationUtility} for HTTP FORM
 * authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HttpFormClientAuthenticationUtility implements HttpClientAuthenticationUtility {

    private volatile String loginPath = null;
    private volatile String username = null;

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyChallenge() {
        // Verify Status is 200
        Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(200);
        // Verify it is the login page
        // Capture URL to submit to
        Function<HttpResponse<T>, HttpResponse<T>> formChallengeVerification = r -> {
            HttpResponse<String> stringResponse = (HttpResponse<String>) r;
            String body = stringResponse.body();
            assertTrue(body.contains("Login Page"), "Expected Login Page Content");
            int pathPrefix = body.indexOf("PATH=");
            loginPath = body.substring(pathPrefix + 5);

            return r;
        };

        return verifyStatusCode.andThen(formChallengeVerification);
    }

    @Override
    public HttpRequest createAuthenticationRequest(URI resource, String username, String password) {
        this.username = username;

        URI realUri;
        try {
            realUri = new URI(resource.getScheme(), resource.getUserInfo(), resource.getHost(), resource.getPort(),
                loginPath, resource.getQuery(), resource.getFragment());
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Unable to construct URI", e);
        }

        String formData = String.format("j_username=%s&j_password=%s",
            URLEncoder.encode(username, StandardCharsets.UTF_8),
            URLEncoder.encode(password, StandardCharsets.UTF_8));

        HttpRequest request = HttpRequest.newBuilder(realUri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(formData))
            .build();

        return request;
    }

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyAuthentication(boolean expectSuccess) {
        if (expectSuccess) {
            Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(200);
            Function<HttpResponse<T>, HttpResponse<T>> verifyNoChallenge = verifyNoChallenge();
            Function<HttpResponse<T>, HttpResponse<T>> verifyPrincipal = verifyPrincipal(username);

            return verifyStatusCode.andThen(verifyNoChallenge).andThen(verifyPrincipal);
        } else {
            Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(200);
            Function<HttpResponse<T>, HttpResponse<T>> formErrorVerification = r -> {
                HttpResponse<String> stringResponse = (HttpResponse<String>) r;
                String body = stringResponse.body();
                assertTrue(body.contains("Login Failed"), "Expected Error Page Content");

                return r;
            };

            return verifyStatusCode.andThen(formErrorVerification);
        }
    }
}
