/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.wildfly.extras.creaper.core.online.CliException;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * Variant of the {@code AbstractAuthenticationSuite} to test the JAAS security realm.
 */
public class JaasSecurityRealmTest extends AbstractAuthenticationSuite {

    private static final String REALM_NAME = "test-jaas-realm";
    private static final String REALM_TYPE = "jaas-realm";

    private volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                                         JaasSecurityRealmTest::registerSecurityRealm, JaasSecurityRealmTest::removeSecurityRealm),
            JaasSecurityRealmTest::realmHttpMechanisms,
            JaasSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        JavaArchive jaasModuleContent = ShrinkWrap.create(JavaArchive.class, "testJaas.jar")
                .addAsResource(new StringAsset("Dependencies: org.wildfly.security"), "META-INF/MANIFEST.MF")
                .addClass(TestJaasLoginModule.class)
                .addClass(TestJaasCallbackHandler.class);
        File jaasModuleJar = new File("testJaas.jar");
        jaasModuleContent.as(ZipExporter.class).exportTo(jaasModuleJar, true);

        Path config = Paths.get("jaas-login.config");
        Files.copy(JaasSecurityRealmTest.class.getResourceAsStream("jaas-login.config"), config, StandardCopyOption.REPLACE_EXISTING);

        try {
            managementClient.executeCli(String.format(
                    "module add --name=testJaasLoginModule --resources=%s --dependencies=org.wildfly.security.elytron",
                    jaasModuleJar.getAbsolutePath()));
        }  catch (CliException e) {
            if (e.getMessage().contains("Module testJaasLoginModule already exists")) {
                // ignore failure, cannot remove module on running server due to file locks on Windows
            } else {
                throw new IOException("Unable to register security realm configuration.", e);
            }
        }

        try {
            managementClient.execute(String.format(
                    "/subsystem=elytron/%s=%s:add(entry=JaasEntry, path=\"%s\", module=testJaasLoginModule, callback-handler=%s)",
                    REALM_TYPE, REALM_NAME, config.toString(), TestJaasCallbackHandler.class.getName())).assertSuccess();

        } catch (CliException e) {
            throw new IOException("Unable to register security realm configuration.", e);
        }

        realmRegistered = true;
    }

    static void removeSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        try {
            if (realmRegistered) {
                managementClient.execute(String.format("/subsystem=elytron/%s=%s:remove", REALM_TYPE, REALM_NAME)).assertSuccess();

                try (Stream<Path> pathStream = Files.walk(Paths.get("server").resolve("modules").resolve("testJaasLoginModule"))) {
                    pathStream.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
                }
                Paths.get("jaas-login.config").toFile().delete();
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
