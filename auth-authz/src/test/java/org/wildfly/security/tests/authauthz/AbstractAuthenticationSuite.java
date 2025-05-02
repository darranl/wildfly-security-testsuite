/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 * Base definition of the {@code Suite} of tests that will be used to run the authentication tests
 * against pre-configured realms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Suite
@SelectClasses(AuthPermutationsSuiteRunner.class)
public abstract class AbstractAuthenticationSuite {

    private static String mode = "";

    static void setMode(final String mode) {
        AbstractAuthenticationSuite.mode = mode;
    }

    static String getMode() {
        return mode;
    }
}
