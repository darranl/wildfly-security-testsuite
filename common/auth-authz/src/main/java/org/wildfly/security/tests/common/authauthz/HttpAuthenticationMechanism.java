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

    BASIC("BASIC"),
    DIGEST_MD5("DIGEST"),
    FORM("FORM"),
    PROGRAMATIC(null);

    private final String mechanismName;

    HttpAuthenticationMechanism(final String mechanismName) {
        this.mechanismName = mechanismName;
    }

    public String getMechanismName() {
        return mechanismName;
    }
}
