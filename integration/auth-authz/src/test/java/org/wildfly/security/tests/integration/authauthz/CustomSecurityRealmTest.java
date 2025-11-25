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
 * Variant of the {@code AbstractAuthenticationSuite} to test the custom security realm.
 */
public class CustomSecurityRealmTest extends AbstractAuthenticationSuite {

    protected static final String REALM_NAME = "test-custom-realm";
    protected static final String REALM_TYPE = "custom-realm";
    protected static final String MODULE_NAME = "testCustomRealmModule";

    protected volatile static boolean realmRegistered = false;

    @BeforeSuite
    public static void beginRealm() {
        register(SecurityRealmRegistrar.create(() -> REALM_TYPE, () -> REALM_NAME,
                        CustomSecurityRealmTest::registerSecurityRealm, CustomSecurityRealmTest::removeSecurityRealm),
                CustomSecurityRealmTest::realmHttpMechanisms,
                CustomSecurityRealmTest::realmSaslMechanisms);
    }

    @AfterSuite
    public static void endRealm() throws IOException {
        register(null, null, null);
    }

    static void registerSecurityRealm(OnlineManagementClient managementClient) throws IOException {
        createAndDeployCustomRealmModuleJar(managementClient, MODULE_NAME);

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

                undeployCustomRealmModuleJar(MODULE_NAME);
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

    // shared with custom modifiable realm tests
    public static void createAndDeployCustomRealmModuleJar(OnlineManagementClient managementClient, String moduleName) throws IOException {
        JavaArchive customRealmModuleContent = ShrinkWrap.create(JavaArchive.class, moduleName + ".jar")
                .addAsResource(new StringAsset("Dependencies: org.wildfly.security"), "META-INF/MANIFEST.MF")
                .addClass(TestCustomSecurityRealm.class);
        File customRealmModuleJar = new File(moduleName + ".jar");
        customRealmModuleContent.as(ZipExporter.class).exportTo(customRealmModuleJar, true);

        try {
            managementClient.executeCli(String.format(
                    "module add --name=%s --resources=%s --dependencies=org.wildfly.security.elytron",
                    moduleName, customRealmModuleJar.getAbsolutePath()));
        }  catch (CliException e) {
            if (e.getMessage().contains(String.format("Module %s already exists", moduleName))) {
                // ignore failure, cannot remove module on running server due to file locks on Windows
            } else {
                throw new IOException("Unable to register security realm configuration.", e);
            }
        }
    }

    // shared with custom modifiable realm tests
    public static void undeployCustomRealmModuleJar(String moduleName) throws IOException {
        try (Stream<Path> pathStream = Files.walk(Paths.get("server").resolve("modules").resolve(moduleName))) {
            pathStream.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
        }
    }
}
