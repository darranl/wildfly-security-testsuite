/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.IOException;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.extras.creaper.core.online.CliException;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * Variant of the {@code AbstractAuthenticationSuite} to test the filesystem security realm.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class FileSystemSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-filesystem-realm";
    private static final String REALM_TYPE = "filesystem-realm";

    private volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                                         FileSystemSecurityRealmTest::registerSecurityRealm, FileSystemSecurityRealmTest::removeSecurityRealm),
            FileSystemSecurityRealmTest::realmHttpMechanisms,
            FileSystemSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try {
            managementClient.execute(String.format("/subsystem=elytron/%s=%s:add(relative-to=jboss.server.config.dir, path=test-realm)", REALM_TYPE, REALM_NAME)).assertSuccess();
            realmRegistered = true;

            // Use a Collector to convert to Iterable so we don't have to worry about the Exceptions.
            for (IdentityDefinition identity : obtainTestIdentities().collect(Collectors.toList())) {
                managementClient.execute(
                    String.format("/subsystem=elytron/%s=%s:add-identity(identity=%s)",
                        REALM_TYPE, REALM_NAME, identity.username())).assertSuccess();
                managementClient.execute(
                    String.format("/subsystem=elytron/%s=%s:set-password(identity=%s, clear={password=%s})",
                        REALM_TYPE, REALM_NAME, identity.username(), identity.password())).assertSuccess();
                managementClient.execute(
                    String.format("/subsystem=elytron/%s=%s:add-identity-attribute(identity=%s, name=groups, value=[admin])",
                        REALM_TYPE, REALM_NAME, identity.username())).assertSuccess();
            }

        } catch (CliException e) {
            throw new IOException("Unable to register security realm configuration.", e);
        }
    }

    static void removeSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try {
            if (realmRegistered) {
                // Use a Collector to convert to Iterable so we don't have to worry about the Exceptions.
                for (IdentityDefinition identity : obtainTestIdentities().collect(Collectors.toList())) {
                    managementClient.execute(
                        String.format("/subsystem=elytron/%s=%s:remove-identity(identity=%s)",
                            REALM_TYPE, REALM_NAME, identity.username())).assertSuccess();
                }

                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove",
                    REALM_TYPE, REALM_NAME)).assertSuccess();
                realmRegistered = false;
            }
        } catch (CliException e) {
            throw new IOException("Unable to remove security realm configuration.", e);
        }
    }

    static Set<SaslAuthenticationMechanism> realmSaslMechanisms() {
        return EnumSet.of(SaslAuthenticationMechanism.PLAIN,
                SaslAuthenticationMechanism.DIGEST_MD5,
                SaslAuthenticationMechanism.DIGEST_SHA,
                SaslAuthenticationMechanism.DIGEST_SHA_256,
                SaslAuthenticationMechanism.DIGEST_SHA_384,
                SaslAuthenticationMechanism.DIGEST_SHA_512);
    }

    static Set<HttpAuthenticationMechanism> realmHttpMechanisms() {
        return EnumSet.of(HttpAuthenticationMechanism.BASIC,
                HttpAuthenticationMechanism.DIGEST_MD5,
                HttpAuthenticationMechanism.FORM,
                HttpAuthenticationMechanism.PROGRAMMATIC);
    }
}
