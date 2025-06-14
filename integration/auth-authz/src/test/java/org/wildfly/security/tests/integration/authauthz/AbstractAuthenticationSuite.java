/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.wildfly.security.tests.common.authauthz.TestContext;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Suite
@SelectClasses(value = { DynamicAuthPermutationsSuiteRunner.class })
public abstract class AbstractAuthenticationSuite {

    private static TestContext testContext = null;

    static String getMode() {
        return "TODO";
    }

    static TestContext getTestContext() {
        return testContext;
    }

}
