/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite.nextIdentity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.jboss.as.arquillian.api.ServerSetup;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.extras.creaper.core.ManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineOptions;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFamily;
import org.wildfly.security.tests.common.authauthz.TestFilter;
import org.wildfly.security.tests.common.authauthz.TransportType;
import org.wildfly.security.tests.common.authauthz.http.HttpTestClient;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite.IdentityDefinition;

/**
 * Runner for brute force attack protection HTTP mechanism testing.
 */
@ServerSetup(BruteForceAuthnProtectionHttpSuiteRunner.ConfigurationServerSetupTask.class)
public class BruteForceAuthnProtectionHttpSuiteRunner extends AbstractHttpSuiteRunner {

    HttpTestClient testClient = HttpTestClient.builder()
                .withToUri(AbstractHttpSuiteRunner::toURI)
                .build();

    static String[] delegateRealmNames() {
        return AbstractAuthenticationSuite.getSecurityRealmRegistrar().getDelegateRealmNames();
    }

    @TestFactory
    Stream<DynamicTest> dynamicHttpTests() {
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<HttpAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms();

        TestFilter testFilter = TestFilter.getInstance();
        String realmType = AbstractAuthenticationSuite.realmType();

        supportedMechnisms.forEach(mechanism -> {
            if (testFilter.shouldRunTest(mechanism, TestFamily.BRUTE_FORCE, "BruteForceAttemptsExceeded")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceAttemptsExceeded(%s)", realmType, mechanism),
                                () -> testHttpBruteForceAttemptsExceeded(mechanism)));
            }
        });

        // tests per realm
        HttpAuthenticationMechanism mechanism = supportedMechnisms.iterator().next();
        if (testFilter.shouldRunTest(TransportType.HTTP, TestFamily.BRUTE_FORCE, "BruteForceDisabled")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceDisabled(%s)", realmType, mechanism),
                                () -> testHttpBruteForceDisabled(mechanism)));
        }
        if (testFilter.shouldRunTest(TransportType.HTTP, TestFamily.BRUTE_FORCE, "BruteForceLockoutInterval")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceLockoutInterval(%s)", realmType, mechanism),
                                () -> testHttpBruteForceLockoutInterval(mechanism)));
        }
        if (testFilter.shouldRunTest(TransportType.HTTP, TestFamily.BRUTE_FORCE, "BruteForceSessionTimeout")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceSessionTimeout(%s)", realmType, mechanism),
                                () -> testHttpBruteForceSessionTimeout(mechanism)));
        }
        if (testFilter.shouldRunTest(TransportType.HTTP, TestFamily.BRUTE_FORCE, "BruteForceMaxCachedSessions")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testHttpBruteForceMaxCachedSessions(%s)", realmType, mechanism),
                                () -> testHttpBruteForceMaxCachedSessions(mechanism)));
        }

        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    public void testHttpBruteForceAttemptsExceeded(final HttpAuthenticationMechanism mechanism) throws Exception {
        IdentityDefinition identityOne = nextIdentity();
        testClient.testHttpSuccess(mechanism, identityOne.username(), identityOne.password());
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityOne.username(), identityOne.password());

        IdentityDefinition identityTwo = nextIdentity();
        testClient.testHttpSuccess(mechanism, identityTwo.username(), identityTwo.password());
        testClient.testHttpBadPassword(mechanism, identityTwo.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityTwo.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityTwo.username(), identityTwo.password());

        // 3 various identites from 3 different realms of distributed-realm
        IdentityDefinition identityThree = nextIdentity();
        testClient.testHttpSuccess(mechanism, identityThree.username(), identityThree.password());
        testClient.testHttpBadPassword(mechanism, identityThree.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityThree.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityThree.username(), identityThree.password());
    }

    public void testHttpBruteForceLockoutInterval(final HttpAuthenticationMechanism mechanism) throws Exception {
        IdentityDefinition identityOne = nextIdentity();
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        Thread.sleep(61000);
        testClient.testHttpSuccess(mechanism, identityOne.username(), identityOne.password());
    }

    public void testHttpBruteForceSessionTimeout(final HttpAuthenticationMechanism mechanism) throws Exception {
        IdentityDefinition identityOne = nextIdentity();
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        Thread.sleep(121000);
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        testClient.testHttpSuccess(mechanism, identityOne.username(), identityOne.password());
    }

    public void testHttpBruteForceMaxCachedSessions(final HttpAuthenticationMechanism mechanism) throws Exception {
        IdentityDefinition identityOne = nextIdentity();
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, identityOne.username(), identityOne.password());

        testClient.testHttpBadPassword(mechanism, nextIdentity().username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, nextIdentity().username(), "passwordX");
        testClient.testHttpBadPassword(mechanism, nextIdentity().username(), "passwordX");

        testClient.testHttpSuccess(mechanism, identityOne.username(), identityOne.password());
    }

    public void testHttpBruteForceDisabled(final HttpAuthenticationMechanism mechanism) throws Exception {
        try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
            for (String realmName : delegateRealmNames()) {
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:add(value=false)", realmName)).assertSuccess();
            }
            new Administration(client).reload();
        }
        try {
            IdentityDefinition identityOne = nextIdentity();
            testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
            testClient.testHttpBadPassword(mechanism, identityOne.username(), "passwordX");
            // This next call should succeed as brute force protection is disabled.
            testClient.testHttpSuccess(mechanism, identityOne.username(), identityOne.password());
        } finally {
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                for (String realmName : delegateRealmNames()) {
                    client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:remove", realmName)).assertSuccess();
                }
                new Administration(client).reload();
            }
        }
    }
    public static class ConfigurationServerSetupTask extends AbstractHttpSuiteRunner.ConfigurationServerSetupTask {

        @Override
        protected Map<String, String> getRequiredSystemProperties() {
            Map<String, String> properties = new HashMap<>();
            for (String realmName : delegateRealmNames()) {
                properties.put(String.format("wildfly.elytron.realm.%s.brute-force.max-failed-attempts", realmName), "2");
                properties.put(String.format("wildfly.elytron.realm.%s.brute-force.lockout-interval", realmName), "1");
                properties.put(String.format("wildfly.elytron.realm.%s.brute-force.session-timeout", realmName), "2");
                properties.put(String.format("wildfly.elytron.realm.%s.brute-force.max-cached-sessions", realmName), "3");
            }
            return properties;
        }

    }
}
