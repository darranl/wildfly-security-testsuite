/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.common.authauthz.http;

import static org.wildfly.security.tests.common.authauthz.http.HttpClientAuthenticationCommon.verifyMechanismChallenge;
import static org.wildfly.security.tests.common.authauthz.http.HttpClientAuthenticationCommon.verifyNoChallenge;
import static org.wildfly.security.tests.common.authauthz.http.HttpClientAuthenticationCommon.verifyPrincipal;
import static org.wildfly.security.tests.common.authauthz.http.HttpClientAuthenticationCommon.verifyStatusCode;
import static org.wildfly.security.tests.common.authauthz.deployment.HelloWorldServlet.X_PASSWORD;
import static org.wildfly.security.tests.common.authauthz.deployment.HelloWorldServlet.X_USERNAME;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.function.Function;

import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;

/**
 * An implementation of {@code HttpClientAuthenticationUtility} for programmatic
 * authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HttpProgrammaticClientAuthenticationUtility implements HttpClientAuthenticationUtility {

    private volatile URI firstRequest;
    private volatile String username;

    @Override
    public HttpRequest createRequest(URI resource) {
        // The first time this is called it will be to the unsecure variant, this is the one we want
        // to call when asked to authenticate.
        if (firstRequest == null) {
            this.firstRequest = resource;
        }

        return HttpRequest.newBuilder(resource).build();
    }

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyChallenge() {
        // For the purpose of testing the BASIC mech will challenge but we are not using it.
        Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(401);
        Function<HttpResponse<T>, HttpResponse<T>> verifyMechanismChallenge = verifyMechanismChallenge(HttpAuthenticationMechanism.BASIC, s -> {});

        return verifyStatusCode.andThen(verifyMechanismChallenge);
    }

    @Override
    public HttpRequest createAuthenticationRequest(URI resource, String username, String password) {
        this.username = username;

        return HttpRequest.newBuilder(firstRequest)
            .header(X_USERNAME, username)
            .header(X_PASSWORD, password)
            .build();
    }

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyAuthentication(boolean expectSuccess) {
        if (expectSuccess) {
            Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(200);
            Function<HttpResponse<T>, HttpResponse<T>> verifyNoChallenge = verifyNoChallenge();
            Function<HttpResponse<T>, HttpResponse<T>> verifyPrincipal = verifyPrincipal(username);

            return verifyStatusCode.andThen(verifyNoChallenge).andThen(verifyPrincipal);
        }

        Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(500);

        return verifyStatusCode;
    }



}
