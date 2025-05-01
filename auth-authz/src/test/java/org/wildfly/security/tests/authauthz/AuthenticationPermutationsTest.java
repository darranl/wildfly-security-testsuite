/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class AuthenticationPermutationsTest {

    public enum Realms {
        CUSTOM, CUSTOM_MODIFIABLE, FILESYSTEM, PROPERTIES, JDBC, LDAP;
    }

    public enum Transports {
        HTTP, SASL;

    }

    public enum Mechanism {
        PLAIN, DIGEST, SCRAM, INTERACTIVE, PROGRAMMATIC;
    }

    @ParameterizedTest
    @MethodSource // Matches the static method with the same name as the test.
    void authenticationTest(final Realms realm, final Transports transport, final Mechanism mechanism) {
        System.out.printf("Realm=%s, Transport=%s, Mechanism=%s \n", realm.name(), transport.name(), mechanism.name());
    }

    private static Stream<Arguments> authenticationTest() {
        List<Arguments> arguments = new ArrayList<>(Realms.values().length * Transports.values().length * Mechanism.values().length);

        for (Realms realm : Realms.values()) {
            for (Transports transport : Transports.values()) {
                for (Mechanism mechanism : Mechanism.values()) {
                    arguments.add(Arguments.of(realm, transport, mechanism));
                }
            }
        }

        return arguments.stream();
    }
}
