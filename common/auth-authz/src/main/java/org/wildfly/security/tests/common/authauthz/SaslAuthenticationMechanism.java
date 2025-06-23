/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.common.authauthz;

/**
 * The SASL authentication mechanisms covered by this testsuite.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public enum SaslAuthenticationMechanism {

    PLAIN("PLAIN"),
    DIGEST_MD5("DIGEST-MD5"),
    DIGEST_SHA_256("DIGEST-SHA-256"),
    DIGEST_SHA_384("DIGEST-SHA-384"),
    DIGEST_SHA("DIGEST-SHA"),
    DIGEST_SHA_512_256("DIGEST-SHA-512-256"),
    DIGEST_SHA_512("DIGEST-SHA-512");

    private final String mechanismName;

    SaslAuthenticationMechanism(final String mechanismName) {
        this.mechanismName = mechanismName;
    }

    public String getMechanismName() {
        return mechanismName;
    }

}
