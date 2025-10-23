/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz.runners;

import static org.wildfly.security.auth.server.SecurityDomain.unregisterClassLoader;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.createSecurityDomain;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.initialised;
import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.server.handlers.PathHandler;
import io.undertow.servlet.Servlets;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.SecurityInfo;
import io.undertow.servlet.api.WebResourceCollection;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.wildfly.elytron.web.undertow.server.servlet.AuthenticationManager;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.basic.BasicMechanismFactory;
import org.wildfly.security.http.digest.DigestMechanismFactory;
import org.wildfly.security.http.form.FormMechanismFactory;
import org.wildfly.security.http.util.AggregateServerMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.deployment.FormErrorServlet;
import org.wildfly.security.tests.common.authauthz.deployment.FormLoginServlet;
import org.wildfly.security.tests.common.authauthz.deployment.HelloWorldServlet;

/**
 * Base class for the Http Suite Runners.
 *
 * This class is responsible for setting up the HTTP server under test.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
abstract class AbstractHttpSuiteRunner {

    private static final String HTTP_HOSTNAME = System.getProperty("http.hostname", "localhost");
    private static final int HTTP_PORT = Integer.getInteger("http.port", 8080);

    static final String ANONYMOUS = "anonymous";
    static final String NULL = "null";
    static final int HTTP_OK = 200;

    private static final String DEPLOYMENT_NAME_TEMPLATE = "%sDeployment.war";
    private static final String CONTEXT_ROOT_PATH_TEMPLATE = "/hello%s";
    private static final String SECURED_PATH = "/secured";
    private static final String UNSECURED_PATH = "/unsecured";

    private static Undertow undertowServer;

    /*
     * Public Utility Methods
     */

    public static String toDeploymentName(final HttpAuthenticationMechanism mechanism) {
        return String.format(DEPLOYMENT_NAME_TEMPLATE, mechanism.name());
    }

    public static String toContextRoot(final HttpAuthenticationMechanism mechanism) {
        return String.format(CONTEXT_ROOT_PATH_TEMPLATE, mechanism.name());
    }

    public static URI toURI(final HttpAuthenticationMechanism mechanism, final boolean secured) throws URISyntaxException {
        return new URI("http", null, HTTP_HOSTNAME, HTTP_PORT,
         toContextRoot(mechanism) + (secured ? SECURED_PATH : UNSECURED_PATH), null, null);
    }

    /**
     * Set up the server process to be used by the tests.
     */
    @BeforeAll
    public static void startServer() {
        System.out.println("AbstractHttpSuiteRunner->startServer()");
        if (!initialised()) {
            System.out.println("AbstractHttpSuiteRunner - NOT INITIALISED");
            return;
        }

        Undertow.Builder undertowBuilder = Undertow.builder();
        undertowBuilder.addHttpListener(HTTP_PORT, HTTP_HOSTNAME);

        PathHandler path = Handlers.path();

        // Common Instances
        // Security Domain
        SecurityDomain securityDomain = createSecurityDomain();
        // Aggregate Mechanism Factory
        Set<HttpAuthenticationMechanism> supportedMechanisms = supportedHttpAuthenticationMechanisms();
        HttpServerAuthenticationMechanismFactory mechanismFactory = createFactory(supportedMechanisms);

        // Create a deployment per supported authentication mechanism with each deployment
        // configured as per the mechanism.
        supportedMechanisms.stream()
                .map(m -> deploymentForMechanism(mechanismFactory, securityDomain, m))
                .forEach(di -> {
                    DeploymentManager deployManager = Servlets.defaultContainer().addDeployment(di);
                    deployManager.deploy();

                    try {
                        path.addPrefixPath(di.getContextPath(), deployManager.start());
                    } catch (ServletException e) {
                        throw new IllegalStateException(e);
                    }
                });

        undertowBuilder.setHandler(path);
        undertowServer = undertowBuilder.build();
        undertowServer.start();
    }

    /**
     * Stop the server process previously started for testing.
     */
    @AfterAll
    public static void stopServer() {
        System.out.println("AbstractHttpSuiteRunner->stopServer()");
        if (undertowServer != null) {
            undertowServer.stop();
            undertowServer = null;
        }
        unregisterClassLoader(AbstractHttpSuiteRunner.class.getClassLoader());
    }

    /*
     * Our Utility Methods
     */

    /**
     * Create a {@code HttpServerAuthenticationMechanismFactory} that supports the specified mechanisms.
     *
     * @param forMechanisms - The mechanisms required to be supported.
     * @return An aggregate {@code HttpServerAuthenticationMechanismFactory} for the supported mechanisms.
     */
    private static HttpServerAuthenticationMechanismFactory createFactory(Set<HttpAuthenticationMechanism> forMechanisms) {
        List<HttpServerAuthenticationMechanismFactory> factories =
               forMechanisms.stream()
                   .map(AbstractHttpSuiteRunner::toFactory)
                   .filter(Objects::nonNull)
                   .toList();

        HttpServerAuthenticationMechanismFactory[] factoryArray = new HttpServerAuthenticationMechanismFactory[factories.size()];
        factories.toArray(factoryArray);

        return new AggregateServerMechanismFactory(factoryArray);
    }

    private static AuthenticationManager createAuthenticationManager(HttpServerAuthenticationMechanismFactory mechanismFactory,
                                                                     SecurityDomain securityDomain,
                                                                     HttpAuthenticationMechanism authenticationMechanism) {
        String mechanismName = authenticationMechanism.getMechanismName();
        if (mechanismName != null) {
            mechanismFactory = new FilterServerMechanismFactory(mechanismFactory, true, mechanismName);
            // TODO Later we may want to wrap and provide properties.
        }

        // TODO We could use the non-deprecated on here but matching WildFly for now.
        HttpAuthenticationFactory httpAuthenticationFactory =  HttpAuthenticationFactory.builder()
                .setFactory(mechanismFactory)
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .build();

        return AuthenticationManager.builder()
                .setHttpAuthenticationFactory(httpAuthenticationFactory)
                .setEnableJaspi(false)
                .build();
    }

    private static DeploymentInfo createDeployment(final String deploymentName, final String contextRoot,
                                                   final String mechanismName) {
        DeploymentInfo deploymentInfo = Servlets.deployment()
                .setClassLoader(HelloWorldServlet.class.getClassLoader())
                .setContextPath(contextRoot)
                .setDeploymentName(deploymentName)
                .addSecurityConstraint(new SecurityConstraint()
                        .addWebResourceCollection(new WebResourceCollection()
                                .addUrlPattern(SECURED_PATH + "/*"))
                        .addRoleAllowed("**")
                        .setEmptyRoleSemantic(SecurityInfo.EmptyRoleSemantic.DENY))
                .addServlets(Servlets.servlet(HelloWorldServlet.class)
                                .addMapping("/")
                                .addMapping(SECURED_PATH)
                                .addMapping(UNSECURED_PATH),
                            Servlets.servlet(FormLoginServlet.class)
                                .addMapping("/loginForm"),
                            Servlets.servlet(FormErrorServlet.class)
                                .addMapping("/errorForm")
                            );

        if (mechanismName != null) {
            deploymentInfo.setLoginConfig(new LoginConfig(mechanismName, "Elytron Realm",
                    "/loginForm", "/errorForm"));
        }

        return deploymentInfo;
    }

    private static DeploymentInfo deploymentForMechanism(HttpServerAuthenticationMechanismFactory mechanismFactory,
                                                         SecurityDomain securityDomain,
                                                         HttpAuthenticationMechanism mechanism) {
        AuthenticationManager authenticationManager = createAuthenticationManager(mechanismFactory, securityDomain, mechanism);

        DeploymentInfo deploymentInfo = createDeployment(toDeploymentName(mechanism),
                toContextRoot(mechanism), mechanism.getMechanismName());

        authenticationManager.configure(deploymentInfo);

        return deploymentInfo;
    }

    private static HttpServerAuthenticationMechanismFactory toFactory(final HttpAuthenticationMechanism mechanism) {
        return switch (mechanism) {
            case BASIC -> new BasicMechanismFactory();
            case DIGEST_MD5 -> new DigestMechanismFactory();
            case FORM -> new FormMechanismFactory();
            default -> null;
        };
    }

}
