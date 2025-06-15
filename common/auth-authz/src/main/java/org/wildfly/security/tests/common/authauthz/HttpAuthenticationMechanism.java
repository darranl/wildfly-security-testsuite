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

    BASIC, DIGEST_MD5, FORM, PROGRAMATIC

}
