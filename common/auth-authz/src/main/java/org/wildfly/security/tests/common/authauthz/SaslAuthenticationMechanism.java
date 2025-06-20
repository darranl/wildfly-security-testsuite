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

    PLAIN,
    DIGEST_MD5,
    DIGEST_SHA_256,
    DIGEST_SHA_384,
    DIGEST_SHA,
    DIGEST_SHA_512_256,
    DIGEST_SHA_512

}
