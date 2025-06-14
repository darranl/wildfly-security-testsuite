/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.security.sasl.SaslServerFactory;

import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.spi.NetworkServerProvider;
import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.sasl.util.ServiceLoaderSaslServerFactory;
import org.wildfly.security.tests.common.authauthz.TestContext;
import org.xnio.OptionMap;
import org.xnio.Options;

/**
 * Base definition of the {@code Suite} of tests that will be used to run the authentication tests
 * against pre-configured realms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Suite
@SelectClasses(value = {DynamicAuthPermutationsSuiteRunner.class})
public abstract class AbstractAuthenticationSuite {

    /*
     * General Constants
     */

    private static final String REALM_NAME = "TestRealm";
    static final OptionMap optionMap = OptionMap.create(Options.SSL_ENABLED, Boolean.FALSE);

    // Test State
    // TODO - This will become the providers needed for testing.
    static Supplier<Provider[]> TEST_PROVIDERS = Security::getProviders;
    private static Endpoint endpoint;
    private static Closeable streamServer;
    private static String providerName;
    private static TestContext testContext;

    private static String mode = "";

    @AfterSuite
    public static void endSuite() throws IOException {
        //TODO - Can we handle all clean up on our own?
        System.out.printf("endSuite() called for mode='%s'\n", mode);
        testContext = null;
        if (streamServer != null) {
            streamServer.close();
            streamServer = null;
        }
        if (endpoint != null) {
            endpoint.close();
            streamServer = null;
        }
    }

    static void setMode(final String mode) {
        AbstractAuthenticationSuite.mode = mode;
    }

    static String getMode() {
        return mode;
    }

    static TestContext getTestContext() {
        return testContext;
    }

    static Endpoint getEndpoint() {
        return endpoint;
    }

    static void registerProvider() {
        final WildFlyElytronProvider provider = new WildFlyElytronProvider();
        Security.addProvider(provider);
        providerName = provider.getName();
    }

    static URI toUri(final String uri) {
        try {
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static SecurityDomain createSecurityDomain(final Supplier<SecurityRealm> securityRealmSupplier) {
        final SecurityDomain.Builder domainBuilder = SecurityDomain.builder();
        domainBuilder.addRealm(REALM_NAME, securityRealmSupplier.get()).build();
        domainBuilder.setDefaultRealmName(REALM_NAME);

        // Just grant login permission for now.
        domainBuilder.setPermissionMapper(
                (p, r) -> PermissionVerifier.from(new LoginPermission()));

        return domainBuilder.build();
    }

    /**
     * Create the test server process backed by the {@code SecurityRealm} available from the
     * {@code securityRealmSupplier}.
     *
     * @param securityRealmSupplier The supplier of the {@code SecurityRealm}.
     */
    static void createTestServer(final Supplier<SecurityRealm> securityRealmSupplier, final Set<String> supportedMechanisms) throws Exception {
        endpoint = Endpoint.builder()
                .setEndpointName(
                        String.format("%sEndpoint", AbstractAuthenticationSuite.class.getName()))
                .build();
        NetworkServerProvider networkServerProvider = endpoint.getConnectionProviderInterface("remote", NetworkServerProvider.class);

        SaslServerFactory saslServerFactory = new ServiceLoaderSaslServerFactory(AbstractAuthenticationSuite.class.getClassLoader());

        SaslAuthenticationFactory saslAuthenticationFactory =  SaslAuthenticationFactory.builder()
                .setSecurityDomain(createSecurityDomain(securityRealmSupplier))
                .setFactory(saslServerFactory)
                .setMechanismConfigurationSelector(mechanismInformation -> supportedMechanisms.contains(mechanismInformation.getMechanismName()) ? MechanismConfiguration.EMPTY : null)
                .build();

        final SSLContext serverContext = SSLContext.getDefault();
        streamServer = networkServerProvider.createServer(new InetSocketAddress("localhost", 30123),
                optionMap, saslAuthenticationFactory, serverContext);

        Map<TestContext.Transport, Set<String>> transportMechMap =
                Collections.singletonMap(TestContext.Transport.SASL,
                        supportedMechanisms);
        testContext = new TestContext(transportMechMap);
    }

    static Stream<IdentityDefinition> obtainTestIdentities() {
        List<IdentityDefinition> identities = new ArrayList<>(10);
        for (int i = 0 ; i < 10 ; i++) {
            identities.add(new IdentityDefinition(String.format("user%d", i),
                    String.format("password%d", i)));
        }

        return identities.stream();
    }

    record IdentityDefinition(String username, String password) {}
}
