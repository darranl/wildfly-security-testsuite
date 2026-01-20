/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.wildfly.security.tests.integration.authauthz.runners.CreaperUtil.onlineManagementClient;
import static org.wildfly.security.tests.integration.authauthz.runners.DeploymentUtility.createJBossWebXml;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;

import javax.naming.Context;
import javax.naming.InitialContext;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.container.annotation.ArquillianTest;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.naming.client.WildFlyInitialContextFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.integration.authauthz.SecurityRealmRegistrar;
import org.wildfly.security.tests.integration.authauthz.deployment.SecuredEjb;
import org.wildfly.security.tests.integration.authauthz.deployment.SecuredEjbRemote;

@ArquillianTest
@ServerSetup(AbstractSaslSuiteRunner.ConfigurationServerSetupTask.class)
@RunAsClient
abstract class AbstractSaslSuiteRunner {

    @Deployment(testable = false)
    public static WebArchive deployment() {
        final String testRealmName = AbstractAuthenticationSuite.getSecurityRealmRegistrar().getPrimaryRealmName();
        final WebArchive war = ShrinkWrap.create(WebArchive.class, String.format("sasl-suite-%s.war", testRealmName))
                .addAsWebInfResource(createJBossWebXml(String.format("ejb-app-domain-%s", testRealmName)), "jboss-web.xml")
                .addClass(SecuredEjb.class)
                .addClass(SecuredEjbRemote.class);
        return war;
    }

    static void performSaslTest(final String mechanism, final String userName, final String password,
            final boolean expectSuccess) throws Exception {

        final String testRealmName = AbstractAuthenticationSuite.getSecurityRealmRegistrar().getPrimaryRealmName();
        final AuthenticationContext authContext = AuthenticationContext.empty()
                .with(MatchRule.ALL, AuthenticationConfiguration.empty()
                        .useName(userName)
                        .usePassword(password)
                        .setSaslMechanismSelector(SaslMechanismSelector.fromString(mechanism))
                );

        final Callable<String> callable = () -> {
            final Hashtable<String, String> jndiProperties = new Hashtable<>();
            jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY, WildFlyInitialContextFactory.class.getName());
            jndiProperties.put(Context.PROVIDER_URL, "remote+http://localhost:8080");
            final Context context = new InitialContext(jndiProperties);
            SecuredEjbRemote reference = (SecuredEjbRemote) context.lookup(String.format("ejb:/sasl-suite-%s/SecuredEjb!%s",
                    testRealmName, SecuredEjbRemote.class.getName()));
            return reference.getPrincipalName();
        };

        try {
            String principalString = authContext.runCallable(callable);
            if (expectSuccess) {
                assertEquals(principalString, userName);
            } else {
                fail(String.format("EJBCLIENT000409 exception for mechanism '%s' should be thrown.", mechanism));
            }
        } catch (Exception e) {
            if (expectSuccess) {
                fail(String.format("Unexpected exception for mechanism '%s': %s", mechanism, e.getMessage()));
            } else {
                assertTrue(e.getMessage().contains("EJBCLIENT000409: No more destinations are available"),
                        "Exception '" + e.getMessage() + "' should contain message 'EJBCLIENT000409: No more destinations are available'");
            }
        }
    }

    public static class ConfigurationServerSetupTask implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String s) throws Exception {

            SecurityRealmRegistrar securityRealmRegistrar = AbstractAuthenticationSuite.getSecurityRealmRegistrar();
            try (OnlineManagementClient client = onlineManagementClient()) {
                securityRealmRegistrar.register(client);
                String testRealmName = securityRealmRegistrar.getPrimaryRealmName();
                List<String> mechanismConfiguration = new ArrayList<>();
                for (SaslAuthenticationMechanism saslMech : AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms()) {
                    mechanismConfiguration.add(String.format(
                            "{mechanism-name=%s,mechanism-realm-configurations=[{\"realm-name\" => \"%s\"}]}",
                            saslMech.getMechanismName(), testRealmName));
                }
                client.execute("/subsystem=logging/logger=org.wildfly.security:add(level=TRACE)").assertSuccess();
                client.execute(String.format("/subsystem=elytron/security-domain=ely-domain-%s:add("
                        + "default-realm=%s, permission-mapper=default-permission-mapper, "
                        + "realms=[{realm=%s, role-decoder=groups-to-roles}])",
                        testRealmName, testRealmName, testRealmName)).assertSuccess();
                client.execute(String.format("/subsystem=elytron/sasl-authentication-factory=sasl-auth-%s:add("
                        + "sasl-server-factory=configured,security-domain=ely-domain-%s, "
                        + "mechanism-configurations=[%s])",
                        testRealmName, testRealmName, String.join(", ", mechanismConfiguration))).assertSuccess();
                client.execute(String.format("/subsystem=ejb3/application-security-domain=ejb-app-domain-%s:add(security-domain=ely-domain-%s)",
                        testRealmName, testRealmName)).assertSuccess();
                client.execute(String.format("/subsystem=remoting/http-connector=http-remoting-connector:write-attribute("
                        + "name=sasl-authentication-factory, value=sasl-auth-%s)", testRealmName)).assertSuccess();

                for (Entry<String, String> entry : getRequiredSystemProperties().entrySet()) {
                    client.execute(String.format("/system-property=%s:add(value=%s)", entry.getKey(), entry.getValue())).assertSuccess();
                }

                new Administration(client).reloadIfRequired();
            }
        }

        @Override
        public void tearDown(ManagementClient managementClient, String s) throws Exception {
            // TODO Can we do something similar to WildFly and restore a SNAPSHOT?
            SecurityRealmRegistrar securityRealmRegistrar = AbstractAuthenticationSuite.getSecurityRealmRegistrar();
            String testRealmName = securityRealmRegistrar.getPrimaryRealmName();
            try (OnlineManagementClient client = onlineManagementClient()) {
                for (String key : getRequiredSystemProperties().keySet()) {
                    client.execute(String.format("/system-property=%s:remove", key)).assertSuccess();
                }

                client.execute("/subsystem=logging/logger=org.wildfly.security:remove").assertSuccess();

                client.execute("/subsystem=remoting/http-connector=http-remoting-connector:write-attribute("
                        + "name=sasl-authentication-factory, value=application-sasl-authentication)").assertSuccess();

                client.execute(String.format("/subsystem=ejb3/application-security-domain=ejb-app-domain-%s:remove", testRealmName)).assertSuccess();
                client.execute(String.format("/subsystem=elytron/sasl-authentication-factory=sasl-auth-%s:remove", testRealmName)).assertSuccess();
                client.execute(String.format("/subsystem=elytron/security-domain=ely-domain-%s:remove", testRealmName)).assertSuccess();
                securityRealmRegistrar.unRegister(client);
                new Administration(client).reloadIfRequired();
            }
        }

        protected Map<String, String> getRequiredSystemProperties() {
            return Collections.emptyMap();
        }
    }
}
