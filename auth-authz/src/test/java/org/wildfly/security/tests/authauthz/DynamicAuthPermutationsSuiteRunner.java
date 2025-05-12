/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

public class DynamicAuthPermutationsSuiteRunner {

    public enum Transport {
        HTTP, SASL;
    }

    @TestFactory
    Stream<DynamicTest> dynamicTests() {
        return Stream.of(Transport.values())
                .map(t ->
                    dynamicTest("My Test",
                            () -> System.out.printf("Running DynamicTest for mode '%s' for transport '%s'\n",
                                    AbstractAuthenticationSuite.getMode(), t.name())));
    }

}
