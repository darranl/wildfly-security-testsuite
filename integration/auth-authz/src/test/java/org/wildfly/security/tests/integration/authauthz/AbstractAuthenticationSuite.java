/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Suite
@SelectClasses(value = { DynamicAuthPermutationsSuiteRunner.class })
public abstract class AbstractAuthenticationSuite {

    static String getMode() {
        return "TODO";
    }

}
