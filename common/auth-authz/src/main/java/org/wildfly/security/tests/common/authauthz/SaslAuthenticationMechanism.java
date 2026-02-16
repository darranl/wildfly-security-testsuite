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
    DIGEST_SHA_512("DIGEST-SHA-512"),
    SCRAM_SHA_1("SCRAM-SHA-1"),
    SCRAM_SHA_256("SCRAM-SHA-256"),
    SCRAM_SHA_384("SCRAM-SHA-384"),
    SCRAM_SHA_512("SCRAM-SHA-512"),
    SCRAM_SHA_1_PLUS("SCRAM-SHA-1-PLUS"),
    SCRAM_SHA_256_PLUS("SCRAM-SHA-256-PLUS"),
    SCRAM_SHA_384_PLUS("SCRAM-SHA-384-PLUS"),
    SCRAM_SHA_512_PLUS("SCRAM-SHA-512-PLUS");

    private final String mechanismName;

    SaslAuthenticationMechanism(final String mechanismName) {
        this.mechanismName = mechanismName;
    }

    public String getMechanismName() {
        return mechanismName;
    }

}
