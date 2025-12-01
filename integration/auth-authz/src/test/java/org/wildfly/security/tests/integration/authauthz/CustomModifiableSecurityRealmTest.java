/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.extras.creaper.core.online.CliException;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * Variant of the {@code AbstractAuthenticationSuite} to test the custom modifiable security realm.
 */
public class CustomModifiableSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-custom-modifiable-realm";
    private static final String REALM_TYPE = "custom-modifiable-realm";
    protected static final String MODULE_NAME = "testCustomModifiableRealmModule";

    private volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                        CustomModifiableSecurityRealmTest::registerSecurityRealm, CustomModifiableSecurityRealmTest::removeSecurityRealm),
                CustomModifiableSecurityRealmTest::realmHttpMechanisms,
                CustomModifiableSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        CustomSecurityRealmTest.createAndDeployCustomRealmModuleJar(managementClient, MODULE_NAME);

        try {
            managementClient.execute(String.format(
                    "/subsystem=elytron/%s=%s:add(module=%s, class-name=%s)",
                    REALM_TYPE, REALM_NAME, MODULE_NAME, TestCustomSecurityRealm.class.getName())).assertSuccess();
            realmRegistered = true;
        } catch (CliException e) {
            throw new IOException("Unable to register security realm configuration.", e);
        }

    }

    static void removeSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try {
            if (realmRegistered) {
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                        REALM_TYPE, REALM_NAME)).assertSuccess();

                CustomSecurityRealmTest.undeployCustomRealmModuleJar(MODULE_NAME);
                new Administration(managementClient).reloadIfRequired();
                realmRegistered = false;
            }
        } catch (CliException | InterruptedException | TimeoutException e) {
            throw new IOException("Unable to remove security realm configuration.", e);
        }
    }

    static Set<SaslAuthenticationMechanism> realmSaslMechanisms() {
        return EnumSet.of(SaslAuthenticationMechanism.PLAIN);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
