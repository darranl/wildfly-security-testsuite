/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.tests.authauthz.framework.SecurityDomainFactory;
import org.wildfly.security.tests.authauthz.framework.TestSecurityDomain;

public class AuthenticationPermutationsTest {

    public enum Realm implements Supplier<TestSecurityDomain> {

        CUSTOM(SecurityDomainFactory::usingCustomSecurityRealm),
        CUSTOM_MODIFIABLE(SecurityDomainFactory::usingOtherSecurityRealm),
        FILESYSTEM(SecurityDomainFactory::usingOtherSecurityRealm),
        PROPERTIES(SecurityDomainFactory::usingOtherSecurityRealm),
        JDBC(SecurityDomainFactory::usingOtherSecurityRealm),
        LDAP(SecurityDomainFactory::usingOtherSecurityRealm);

        private final Supplier<TestSecurityDomain> supplier;

        Realm(final Supplier<TestSecurityDomain> supplier) {
            this.supplier = supplier;
        }

        @Override
        public TestSecurityDomain get() {
            return supplier != null ? supplier.get() : null;
        }
    }

    public enum Transport {
        HTTP, SASL;

    }

    public enum Mechanism {
        PLAIN, DIGEST, SCRAM, INTERACTIVE, PROGRAMMATIC;
    }

    @ParameterizedTest
    @MethodSource // Matches the static method with the same name as the test.
    void authenticationTest(final Realm realm, final Transport transport, final Mechanism mechanism) {
        System.out.printf("Realm=%s, Transport=%s, Mechanism=%s \n", realm.name(), transport.name(), mechanism.name());

        List<Closeable> closeables = new ArrayList<>();
        try {


        } finally {

        }
        // Test Runner
        // Set up SecurityDoman with specific realm.
        //   Maybe needs TestContainer
        // Set up entry point HTTP / SASL
        // Configure Client

        // Test Scenarios
        //   Successful Auth
        //   Unsucsseful Auth
        //     Bad Username
        //     Bad Password
        //   Brute Force
        //     Verify lockout
        //     Force reset, verify success
    }

    private static SecurityDomain createSecurityDomain(Supplier<TestSecurityDomain> testDomain, List<Closeable> closeables) {
        TestSecurityDomain testDomainInstance = testDomain.get();
        if (testDomainInstance != null) {
            closeables.add(testDomainInstance);

            return testDomainInstance.get();
        }

        return null;
    }

    private static Stream<Arguments> authenticationTest() {
        List<Arguments> arguments = new ArrayList<>(Realm.values().length * Transport.values().length * Mechanism.values().length);

        for (Realm realm : Realm.values()) {
            for (Transport transport : Transport.values()) {
                for (Mechanism mechanism : Mechanism.values()) {
                    if (isSupportedPermutation(realm, transport, mechanism)) {
                        arguments.add(Arguments.of(realm, transport, mechanism));
                    }
                }
            }
        }

        return arguments.stream();
    }

    private static boolean isSupportedPermutation(final Realm realm, final Transport transport, final Mechanism mechanism) {
        if ( (transport == Transport.HTTP && mechanism == Mechanism.SCRAM)
            || transport == Transport.SASL && (mechanism == Mechanism.INTERACTIVE || mechanism == Mechanism.PROGRAMMATIC) ) {
                return false;
        }
        return true;
    }
}
