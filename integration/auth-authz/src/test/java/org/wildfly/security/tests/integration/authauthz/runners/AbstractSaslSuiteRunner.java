/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Hashtable;
import java.util.concurrent.Callable;
import javax.naming.Context;
import javax.naming.InitialContext;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.container.annotation.ArquillianTest;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.wildfly.extras.creaper.core.ManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.OnlineOptions;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.naming.client.WildFlyInitialContextFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.SaslMechanismSelector;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;
import org.wildfly.security.tests.integration.authauthz.deployment.SecuredEjb;
import org.wildfly.security.tests.integration.authauthz.deployment.SecuredEjbRemote;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;

@ArquillianTest
@ServerSetup(AbstractSaslSuiteRunner.ConfigurationServerSetupTask.class)
@RunAsClient
abstract class AbstractSaslSuiteRunner {

    @Deployment(testable = false)
    public static EnterpriseArchive deployment() {
        EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, "sasl-suite.ear");
        for (SaslAuthenticationMechanism saslMech : AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms()) {
            WebArchive war = ShrinkWrap.create(WebArchive.class, String.format("sasl-suite-%s.war", saslMech.getMechanismName()))
                .addAsWebInfResource(createJBossWebXml(String.format("ejb-app-domain-%s", saslMech.getMechanismName())), "jboss-web.xml")
                .addClass(SecuredEjb.class)
                .addClass(SecuredEjbRemote.class);
            ear.addAsModule(war);
        }
        return ear;
    }

    protected void performSaslTest(final String mechanism, final String userName, final String password,
            final boolean expectSuccess) throws Exception {

        try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
            client.execute(String.format("/subsystem=remoting/http-connector=http-remoting-connector:write-attribute("
                    + "name=sasl-authentication-factory, value=sasl-auth-%s)", mechanism)).assertSuccess();
            new Administration(client).reloadIfRequired();
        }

        AuthenticationContext authContext = AuthenticationContext.empty()
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
            SecuredEjbRemote reference = (SecuredEjbRemote) context.lookup(String.format("ejb:sasl-suite/sasl-suite-%s/SecuredEjb!%s",
                    mechanism, SecuredEjbRemote.class.getName()));
            return reference.getPrincipalName();
        };

        try {
            String principalString = authContext.runCallable(callable);
            assertEquals(principalString, userName);
        } catch (Exception e) {
            if (expectSuccess) {
                fail(String.format("Unexpected exception for mechanism '%s': %s", mechanism, e.getMessage()));
            } else {
                assertTrue(e.getMessage().contains("EJBCLIENT000409: No more destinations are available"),
                        "Exception '" + e.getMessage() + "' should contain message 'EJBCLIENT000409: No more destinations are available'");
            }
        }
    }

    public static StringAsset createJBossWebXml(String securityDomain) {
        return new StringAsset(String.format("<jboss-web><security-domain>%s</security-domain></jboss-web>", securityDomain));
    }

    public static class ConfigurationServerSetupTask implements ServerSetupTask {

        private String testRealmName;

        @Override
        public void setup(org.jboss.as.arquillian.container.ManagementClient managementClient, String s) throws Exception {
            
            testRealmName = AbstractAuthenticationSuite.getSecurityRealmSupplier().get();
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                for (SaslAuthenticationMechanism saslMech : AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms()) {
                    String saslMechName = saslMech.getMechanismName();
                    client.execute(String.format("/subsystem=elytron/security-domain=ely-domain-%s:add("
                            + "default-realm=%s, permission-mapper=default-permission-mapper, "
                            + "realms=[{realm=%s, role-decoder=groups-to-roles}])",
                            saslMechName, testRealmName, testRealmName)).assertSuccess();
                    client.execute(String.format("/subsystem=elytron/sasl-authentication-factory=sasl-auth-%s:add("
                            + "sasl-server-factory=configured,security-domain=ely-domain-%s, "
                            + "mechanism-configurations=[{mechanism-name=%s,mechanism-realm-configurations=[{\"realm-name\" => \"%s\"}]}])",
                            saslMechName, saslMechName, saslMechName, testRealmName)).assertSuccess();
                    client.execute(String.format("/subsystem=ejb3/application-security-domain=ejb-app-domain-%s:add(security-domain=ely-domain-%s)",
                            saslMechName, saslMechName)).assertSuccess();
                }
            }
        }

        @Override
        public void tearDown(org.jboss.as.arquillian.container.ManagementClient managementClient, String s) throws Exception {
            try (OnlineManagementClient client = ManagementClient.online(OnlineOptions.standalone().localDefault().build())) {
                client.execute("/subsystem=remoting/http-connector=http-remoting-connector:write-attribute("
                    + "name=sasl-authentication-factory, value=application-sasl-authentication)").assertSuccess();

                for (SaslAuthenticationMechanism saslMech : AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms()) {
                    String saslMechName = saslMech.getMechanismName();
                    client.execute(String.format("/subsystem=ejb3/application-security-domain=ejb-app-domain-%s:remove", saslMechName)).assertSuccess();
                    client.execute(String.format("/subsystem=elytron/sasl-authentication-factory=sasl-auth-%s:remove", saslMechName)).assertSuccess();
                    client.execute(String.format("/subsystem=elytron/security-domain=ely-domain-%s:remove", saslMechName)).assertSuccess();
                    client.execute(String.format("/subsystem=elytron/%s=%s:remove", AbstractAuthenticationSuite.realmType(), testRealmName)).assertSuccess();
                }
            }
        }
    }
}
