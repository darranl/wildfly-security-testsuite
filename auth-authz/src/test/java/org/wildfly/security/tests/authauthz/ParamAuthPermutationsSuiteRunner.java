/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class ParamAuthPermutationsSuiteRunner {

    public enum Transport {
        HTTP, SASL;
    }

    @ParameterizedTest
    @EnumSource(Transport.class)
    public void runnerTest(final Transport transport) {
        System.out.printf("Running ParameterizedTest for mode '%s' for transport '%s'\n", AbstractAuthenticationSuite.getMode(), transport.name());
    }
}
