/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.framework;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.wildfly.security.mechanism.digest.DigestUtil.userRealmPasswordDigest;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.AUTHORIZATION;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyMechanismChallenge;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyNoChallenge;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyPrincipal;
import static org.wildfly.security.tests.authauthz.framework.HttpClientAuthenticationCommon.verifyStatusCode;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import org.apache.directory.api.util.Strings;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;

/**
 * An implementation of {@code HttpClientAuthenticationUtility} for HTTP DIGEST
 * authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HttpDigestClientAuthenticationUtility implements HttpClientAuthenticationUtility {

    // TODO does this need to be dynamic?
    private static final byte COLON = ':';
    private static final String ALGORITHM = "algorithm";
    private static final String CNONCE = "cnonce";
    private static final String GET = "GET";
    private static final String MD5 = "MD5";
    private static final String NC = "nc";
    private static final String NONCE = "nonce";
    private static final String OPAQUE = "opaque";
    private static final String QOP = "qop";
    private static final String REALM = "realm";
    private static final String RESPONSE = "response";
    private static final String URI = "uri";
    private static final String USERNAME = "username";
    private static final String expectedRealm = "Elytron Realm";

    // In real world scenarios this must be securely generated and unique.
    private static final String CNONCE_VALUE = "Security Testsuite";
    private static final String QOP_VALUE = "auth";

    private final MessageDigest messageDigest;

    // Cached Data
    private volatile String username = null;
    private volatile String password = null;
    // Challenge
    private volatile Map<String, String> challengeData = null;
    private volatile String currentNonce = null;
    private volatile int nonceCount = 1;

    HttpDigestClientAuthenticationUtility() {
        try {
            this.messageDigest = MessageDigest.getInstance(MD5);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to initialise.", e);
        }
    }

    private void processChallenge(final String challenge) {
        Map<String, String> processedData = new HashMap<>();
        String[] parts = challenge.split(",");
        for (String currentPart : parts) {
            currentPart = currentPart.trim();
            String[] tokens = splitToken(currentPart);
            processedData.put(tokens[0], tokens[1]);
        }

        if (challengeData == null) {
            challengeData = processedData;
        } else {
            // Here we get to track updates e.g. updated nonces.
            challengeData.putAll(processedData);
        }

        if (!Strings.equals(challengeData.get(NONCE), currentNonce)) {
            // New nonce so start counting again.
            currentNonce = challengeData.get(NONCE);
            nonceCount = 1;
        }
    }

    private String[] splitToken(final String token) {
        String[] tokens = new String[2];

        int equalsLocation = token.indexOf('=');
        tokens[0] = token.substring(0, equalsLocation);

        String value = token.substring(equalsLocation + 1, token.length());
        if (value.startsWith("\"") && value.endsWith("\"")  ) {
            value = value.substring(1, value.length() - 1);
        };
        tokens[1] = value;

        return tokens;
    }

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyChallenge() {
        Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(401);

        Consumer<String> challengeVerifier = s -> {
            assertEquals(expectedRealm, challengeData.get(REALM), "Expected Realm Name");
        };

        Function<HttpResponse<T>, HttpResponse<T>> verifyMechanismChallenge =
            verifyMechanismChallenge(HttpAuthenticationMechanism.DIGEST_MD5, ((Consumer<String>)(this::processChallenge)).andThen(challengeVerifier));

        return verifyStatusCode.andThen(verifyMechanismChallenge);
    }

    @Override
    public HttpRequest createAuthenticationRequest(final URI resource, final String username, final String password) {
        this.username = username;
        this.password = password;

        // All DIGEST auth calls need the username and password so now that we have cached these we can use
        // createRequest(URI); This method will also verify we did previously receive a challenge.
        return createRequest(resource);
    }

    @Override
    public <T> Function<HttpResponse<T>, HttpResponse<T>> verifyAuthentication(boolean expectSuccess) {
        if (expectSuccess) {
            Function<HttpResponse<T>, HttpResponse<T>> verifyStatusCode = verifyStatusCode(200);
            Function<HttpResponse<T>, HttpResponse<T>> verifyNoChallenge = verifyNoChallenge();
            Function<HttpResponse<T>, HttpResponse<T>> verifyPrincipal = verifyPrincipal(username);

            return verifyStatusCode.andThen(verifyNoChallenge).andThen(verifyPrincipal);
        } else {
            return verifyChallenge();
        }
    }

    @Override
    public HttpRequest createRequest(final URI resource) {
        assertNotNull(challengeData, "Challenge data is required");
        assertFalse(challengeData.isEmpty(), "Challenge data must be populated");

        return HttpRequest.newBuilder(resource)
            .header(AUTHORIZATION, createResponseToChallenge(resource))
            .build();
    }

    private String createResponseToChallenge(final URI resource) {
        StringBuilder sb = new StringBuilder(HttpAuthenticationMechanism.DIGEST_MD5.getChallenge());

        String uri = resource.getPath();
        // Don't try and refactor these into the main response digest as these all use the same
        // MessageDigest instance.
        byte[] hA1 = calculateHA1();
        byte[] hA2 = calculateHA2(uri);
        // MessageDigest is now ours
        messageDigest.update(hA1);
        messageDigest.update(COLON);
        String nonce = challengeData.get(NONCE);
        messageDigest.update(nonce.getBytes(UTF_8));
        // Assume we will use qop of auth
        messageDigest.update(COLON);
        Integer nonceCountInt = nonceCount++;
        String nonceCount = String.format("%08d", nonceCountInt);
        messageDigest.update(nonceCount.getBytes(UTF_8));
        messageDigest.update(COLON);
        messageDigest.update(CNONCE_VALUE.getBytes(UTF_8));
        messageDigest.update(COLON);
        messageDigest.update(QOP_VALUE.getBytes(UTF_8));
        messageDigest.update(COLON);

        byte[] responseDigest = toHexBytes(messageDigest.digest(hA2));
        // Remaining fields needed.
        String realm = challengeData.get(REALM);
        String opaque = challengeData.get(OPAQUE);

        append(sb, USERNAME, username, true, false);
        append(sb, REALM, realm, true, false);
        append(sb, NONCE, nonce, true, false);
        append(sb, URI, uri, true, false);
        append(sb, CNONCE, CNONCE_VALUE, true, false);
        append(sb, NC, nonceCount, false, false);
        append(sb, QOP, QOP_VALUE, false, false);
        append(sb, RESPONSE, new String(responseDigest, UTF_8), true, false);
        append(sb, OPAQUE, opaque, true, false);
        append(sb, ALGORITHM, MD5, false, true);

        return sb.toString();
    }

    private void append(StringBuilder sb, String key, String value, boolean quoted, boolean last) {
        sb.append(' ');
        sb.append(key);
        sb.append('=');
        sb.append(quoted ? String.format("\"%s\"", value) : value);
        if (!last) {
            sb.append(',');
        }
    }

    private byte[] calculateHA1() {
        String realm = challengeData.get(REALM);

        return toHexBytes(userRealmPasswordDigest(messageDigest, username, realm, password.toCharArray()));
    }

    private byte[] calculateHA2(final String uri) {
        messageDigest.update(GET.getBytes(UTF_8));
        messageDigest.update(COLON);

        return toHexBytes(messageDigest.digest(uri.getBytes(UTF_8)));
    }

    private byte[] toHexBytes(final byte[] input) {
        return ByteIterator.ofBytes(input).hexEncode().drainToString().getBytes(UTF_8);
    }


}
