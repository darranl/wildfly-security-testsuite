/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.jboss.as.arquillian.api.ServerSetup;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.wildfly.extras.creaper.core.ManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineOptions;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.TestFilter;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;

@ServerSetup(BruteForceAuthnProtectionSaslSuiteRunner.ConfigurationServerSetupTask.class)
public class BruteForceAuthnProtectionSaslSuiteRunner extends AbstractSaslSuiteRunner {

    @TestFactory
    Stream<DynamicTest> dynamicSaslTests() {
        List<DynamicTest> dynamicTests = new ArrayList<>();

        Set<SaslAuthenticationMechanism> supportedMechnisms =
                AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms();

        TestFilter testFilter = TestFilter.getInstance();

        String realmType = AbstractAuthenticationSuite.realmType();

        // tests per mechanism
        supportedMechnisms.forEach(s -> {
            if (testFilter.shouldRunTest(s, "BruteForceAttemptsExceeded")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceAttemptsExceeded(%s)", realmType, s),
                                () -> testSaslBruteForceAttemptsExceeded(s)));
            }
        });

        // tests per realm
        SaslAuthenticationMechanism mechanism = supportedMechnisms.iterator().next();
        if (testFilter.shouldRunTest("BruteForceDisabled")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceDisabled(%s)", realmType, mechanism),
                                () -> testSaslBruteForceDisabled(mechanism)));
        }
        if (testFilter.shouldRunTest("testSaslBruteForceLockoutInterval")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceLockoutInterval(%s)", realmType, mechanism),
                                () -> testSaslBruteForceLockoutInterval(mechanism)));
        }
        if (testFilter.shouldRunTest("testSaslBruteForceSessionTimeout")) {
                dynamicTests.add(
                        dynamicTest(String.format("[%s] testSaslBruteForceSessionTimeout(%s)", realmType, mechanism),
                                () -> testSaslBruteForceSessionTimeout(mechanism)));
        }

        if (dynamicTests.isEmpty()) {
            System.out.println("No Tests Added - Adding a Dummy");
            dynamicTests.add(dynamicTest("[DUMMY] DUMMY TEST", () -> {}));
        }

        return dynamicTests.stream();
    }

    public void testSaslBruteForceAttemptsExceeded(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceAttemptsExceeded(%s)\n", mechanism);
        configureHttpConnectorSaslAuthn(mechanism.getMechanismName());

        testSaslEjbConnection(mechanism.getMechanismName(), "user1", "passwordX", false);
        testSaslEjbConnection(mechanism.getMechanismName(), "user1", "passwordX", false);
        testSaslEjbConnection(mechanism.getMechanismName(), "user1", "password1", false);

        // TODO investigate why this does not work
        //testSaslEjbConnection(mechanism.getMechanismName(), "user2", "password2", true);
        testSaslEjbConnection(mechanism.getMechanismName(), "user2", "passwordX", false);
        testSaslEjbConnection(mechanism.getMechanismName(), "user2", "passwordX", false);
        testSaslEjbConnection(mechanism.getMechanismName(), "user2", "password2", false);
    }

    // TODO is it ok to test this just for one mech per realm? Also, it would be great if we could set short lockout interval for tests (1 minute now).
    public void testSaslBruteForceLockoutInterval(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceLockoutInterval(%s)\n", mechanism);

        configureHttpConnectorSaslAuthn(mechanism.getMechanismName());
        testSaslEjbConnection(mechanism.getMechanismName(), "user3", "passwordX", false);
        testSaslEjbConnection(mechanism.getMechanismName(), "user3", "passwordX", false);
        Thread.sleep(61000);
        testSaslEjbConnection(mechanism.getMechanismName(), "user3", "password3", true);
    }

    // TODO is it ok to test this just for one mech per realm? Also, it would be great if we could set short session timout for tests (1 minute now).
    public void testSaslBruteForceSessionTimeout(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceSessionTimeout(%s)\n", mechanism);

        configureHttpConnectorSaslAuthn(mechanism.getMechanismName());
        testSaslEjbConnection(mechanism.getMechanismName(), "user4", "passwordX", false);
        Thread.sleep(61000);
        testSaslEjbConnection(mechanism.getMechanismName(), "user4", "passwordX", false);
        testSaslEjbConnection(mechanism.getMechanismName(), "user4", "password4", true);
    }

    public void testSaslBruteForceDisabled(final SaslAuthenticationMechanism mechanism) throws Exception {
        System.out.printf("testSaslBruteForceDisabled(%s)\n", mechanism);
        try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
            client.execute(String.format("/subsystem=remoting/http-connector=http-remoting-connector:write-attribute("
                    + "name=sasl-authentication-factory, value=sasl-auth-%s)", mechanism.getMechanismName())).assertSuccess();
            client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:add(value=false)", testRealmName)).assertSuccess();
            new Administration(client).reload();
        }

        try {
            testSaslEjbConnection(mechanism.getMechanismName(), "user5", "passwordX", false);
            testSaslEjbConnection(mechanism.getMechanismName(), "user5", "passwordX", false);
            testSaslEjbConnection(mechanism.getMechanismName(), "user5", "password5", true);
        } finally {
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.enabled:remove", testRealmName)).assertSuccess();
                new Administration(client).reload();
            }
        }
    }

    public static class ConfigurationServerSetupTask extends AbstractSaslSuiteRunner.ConfigurationServerSetupTask {

        @Override
        public void setup(org.jboss.as.arquillian.container.ManagementClient managementClient, String s) throws Exception {
            super.setup(managementClient, s);
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.max-failed-attempts:add(value=1)", testRealmName)).assertSuccess();
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.lockout-interval:add(value=1)", testRealmName)).assertSuccess();
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.session-timeout:add(value=1)", testRealmName)).assertSuccess();
                new Administration(client).reload();
            }
        }

        @Override
        public void tearDown(org.jboss.as.arquillian.container.ManagementClient managementClient, String s) throws Exception {
            super.tearDown(managementClient, s);
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.max-failed-attempts:remove", testRealmName)).assertSuccess();
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.lockout-interval:remove", testRealmName)).assertSuccess();
                client.execute(String.format("/system-property=wildfly.elytron.realm.%s.brute-force.session-timeout:remove", testRealmName)).assertSuccess();
            }
        }
    }
}
