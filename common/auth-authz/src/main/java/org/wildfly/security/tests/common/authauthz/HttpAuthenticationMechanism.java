/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.common.authauthz;

/**
 * The HTTP authentication mechanisms used in this testsuite.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public enum HttpAuthenticationMechanism {

    BASIC("BASIC", "Basic"),
    DIGEST_MD5("DIGEST", "Digest"),
    FORM("FORM", null),
    // For the purpose of testing we need it to enable a mech even if we will not use it.
    PROGRAMMATIC("BASIC", null);

    private final String mechanismName;
    private final String challenge;

    HttpAuthenticationMechanism(final String mechanismName, final String challenge) {
        this.mechanismName = mechanismName;
        this.challenge = challenge;
    }

    public String getMechanismName() {
        return mechanismName;
    }

    public String getChallenge() {
        return challenge;
    }
}
