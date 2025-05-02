/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import org.junit.jupiter.api.Test;

public class AuthPermutationsSuiteRunner {

    @Test
    public void runnerTest() {
        System.out.printf("Running test for mode '%s'\n", AbstractAuthenticationSuite.getMode());
    }
}
