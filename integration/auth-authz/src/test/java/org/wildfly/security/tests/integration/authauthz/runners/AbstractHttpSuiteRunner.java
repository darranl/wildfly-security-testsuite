/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz.runners;

import static org.wildfly.security.tests.integration.authauthz.runners.DeploymentUtility.createJBossWebXml;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.container.annotation.ArquillianTest;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.Asset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.descriptor.api.Descriptors;
import org.jboss.shrinkwrap.descriptor.api.webapp31.WebAppDescriptor;
import org.jboss.shrinkwrap.descriptor.api.webcommon31.ServletType;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.deployment.FormErrorServlet;
import org.wildfly.security.tests.common.authauthz.deployment.FormLoginServlet;
import org.wildfly.security.tests.common.authauthz.deployment.HelloWorldServlet;
import org.wildfly.security.tests.integration.authauthz.AbstractAuthenticationSuite;

/**
 * The base "runner" to set up HTTP authentication based testing.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@ArquillianTest
// TODO Add @ServerSetup
@RunAsClient
abstract class AbstractHttpSuiteRunner {

    private static final String SECURED_PATH = "/secured";
    private static final String UNSECURED_PATH = "/unsecured";

    @Deployment(testable = false)
    public static EnterpriseArchive deployment() {
        EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, "http-suite.ear");
        for (HttpAuthenticationMechanism httpMech : AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms()) {
            WebArchive war = ShrinkWrap.create(WebArchive.class, String.format("http-suite-%s.war", httpMech.getMechanismName()))
                .addAsWebInfResource(createJBossWebXml(String.format("web-app-domain-%s", httpMech.getMechanismName())), "jboss-web.xml")
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
                .roleName("**");

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
}
