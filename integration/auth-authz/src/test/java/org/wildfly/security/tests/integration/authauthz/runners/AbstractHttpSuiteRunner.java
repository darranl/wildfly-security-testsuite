/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.wildfly.security.tests.integration.authauthz.runners.CreaperUtil.onlineManagementClient;
import static org.wildfly.security.tests.integration.authauthz.runners.DeploymentUtility.createJBossWebXml;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.container.annotation.ArquillianTest;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.Asset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.descriptor.api.Descriptors;
import org.jboss.shrinkwrap.descriptor.api.webapp31.WebAppDescriptor;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.deployment.FormErrorServlet;
import org.wildfly.security.tests.common.authauthz.deployment.FormLoginServlet;
import org.wildfly.security.tests.common.authauthz.deployment.HelloWorldServlet;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;
import org.wildfly.security.tests.integration.authauthz.SecurityRealmRegistrar;

/**
 * The base "runner" to set up HTTP authentication based testing.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@ArquillianTest
@ServerSetup(AbstractHttpSuiteRunner.ConfigurationServerSetupTask.class)
@RunAsClient
abstract class AbstractHttpSuiteRunner {

    // TODO Can we discover / inject these?
    private static final String HTTP_HOSTNAME = System.getProperty("http.hostname", "localhost");
    private static final int HTTP_PORT = Integer.getInteger("http.port", 8080);

    private static final String DEPLOYMENT_NAME_TEMPLATE = "http-suite-%s.war";
    private static final String CONTEXT_ROOT_PATH_TEMPLATE = "/http-suite-%s";
    private static final String SECURED_PATH = "/secured";
    private static final String UNSECURED_PATH = "/unsecured";

    /*
     * Public Utility Methods
     */

    public static String toContextRoot(final HttpAuthenticationMechanism mechanism) {
        return String.format(CONTEXT_ROOT_PATH_TEMPLATE, mechanism.getMechanismName());
    }

    public static URI toURI(final HttpAuthenticationMechanism mechanism, final boolean secured) throws URISyntaxException {
        return new URI("http", null, HTTP_HOSTNAME, HTTP_PORT,
         toContextRoot(mechanism) + (secured ? SECURED_PATH : UNSECURED_PATH), null, null);
    }

    @Deployment(testable = false)
    public static EnterpriseArchive deployment() {
        EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, "http-suite.ear");
        for (HttpAuthenticationMechanism httpMech : AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms()) {
            WebArchive war = ShrinkWrap.create(WebArchive.class, String.format(DEPLOYMENT_NAME_TEMPLATE, httpMech.getMechanismName()))
                .addAsWebInfResource(createJBossWebXml("web-app-domain"), "jboss-web.xml")
                .addClasses(HelloWorldServlet.class, FormLoginServlet.class, FormErrorServlet.class)
                .addAsWebInfResource(createWebXml(httpMech), "web.xml")
                ;
            ear.addAsModule(war);
        }
        return ear;
    }

    private static Asset createWebXml(final HttpAuthenticationMechanism authenticationMechanism) {
        WebAppDescriptor webXml = Descriptors.create(WebAppDescriptor.class);

        // HelloWorldServlet
        webXml.createServlet()
            .servletName(HelloWorldServlet.class.getSimpleName())
            .servletClass(HelloWorldServlet.class.getName());

        webXml.createServletMapping()
            .servletName(HelloWorldServlet.class.getSimpleName())
            .urlPattern("/", SECURED_PATH, UNSECURED_PATH);

        // FormLoginServlet
        webXml.createServlet()
            .servletName(FormLoginServlet.class.getSimpleName())
            .servletClass(FormLoginServlet.class.getName());

        webXml.createServletMapping()
            .servletName(FormLoginServlet.class.getSimpleName())
            .urlPattern("/loginForm");

        // FormErrorServlet
        webXml.createServlet()
            .servletName(FormErrorServlet.class.getSimpleName())
            .servletClass(FormErrorServlet.class.getName());

        webXml.createServletMapping()
            .servletName(FormErrorServlet.class.getSimpleName())
            .urlPattern("/errorForm");

        // Security Constraints
        webXml.createSecurityConstraint()
            .createWebResourceCollection()
                .urlPattern(SECURED_PATH + "/*")
                .up()
            .getOrCreateAuthConstraint()
                .roleName("admin");

        // LoginConfig
        String mechanismName = authenticationMechanism.getMechanismName();
        if (mechanismName != null) {
            webXml.createLoginConfig()
                .authMethod(mechanismName)
                .realmName("Elytron Realm")
                .getOrCreateFormLoginConfig()
                    .formLoginPage("/loginForm")
                    .formErrorPage("/errorForm");
        }

        String webXmlString = webXml.exportAsString();
        System.out.println(webXmlString);
        return new StringAsset(webXmlString);
    }

    public static class ConfigurationServerSetupTask implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            SecurityRealmRegistrar securityRealmRegistrar = AbstractAuthenticationSuite.getSecurityRealmRegistrar();
            // To begin with we have no domain or application-security-domain specifics so use a
            // single definition.
            try (OnlineManagementClient client = onlineManagementClient()) {
                securityRealmRegistrar.register(client);
                String testRealmName = securityRealmRegistrar.getRealmName();
                client.execute(String.format("/subsystem=elytron/security-domain=ely-domain-http:add("
                            + "default-realm=%s, permission-mapper=default-permission-mapper, "
                            + "realms=[{realm=%s, role-decoder=groups-to-roles}])",
                            testRealmName, testRealmName)).assertSuccess();

                client.execute(String.format("/subsystem=undertow/application-security-domain=%s:add(security-domain=%s)",
                        "web-app-domain", "ely-domain-http")).assertSuccess();

                client.execute("/subsystem=logging/logger=org.wildfly.security:add(level=TRACE)").assertSuccess();
                client.execute("/subsystem=logging/logger=org.wildfly.extension.elytron:add(level=TRACE)").assertSuccess();
                client.execute("/subsystem=logging/logger=io.undertow:add(level=TRACE)").assertSuccess();

                for (Entry<String, String> entry : getRequiredSystemProperties().entrySet()) {
                    client.execute(String.format("/system-property=%s:add(value=%s)", entry.getKey(), entry.getValue())).assertSuccess();
                }

                new Administration(client).reload();
            }
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            SecurityRealmRegistrar securityRealmRegistrar = AbstractAuthenticationSuite.getSecurityRealmRegistrar();
            // TODO Can we do something similar to WildFly and restore a SNAPSHOT?
            try (OnlineManagementClient client = onlineManagementClient()) {
                for (String key : getRequiredSystemProperties().keySet()) {
                    client.execute(String.format("/system-property=%s:remove", key)).assertSuccess();
                }

                client.execute("/subsystem=logging/logger=io.undertow:remove").assertSuccess();
                client.execute("/subsystem=logging/logger=org.wildfly.extension.elytron:remove").assertSuccess();
                client.execute("/subsystem=logging/logger=org.wildfly.security:remove").assertSuccess();

                client.execute("/subsystem=undertow/application-security-domain=web-app-domain:remove").assertSuccess();
                client.execute("/subsystem=elytron/security-domain=ely-domain-http:remove").assertSuccess();
                securityRealmRegistrar.unRegister(client);
            }
        }

        protected Map<String, String> getRequiredSystemProperties() {
            return Collections.emptyMap();
        }

    }

}
