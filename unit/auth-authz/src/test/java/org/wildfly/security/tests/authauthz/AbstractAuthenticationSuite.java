/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.tests.authauthz.runners.StandardHttpSuiteRunner;
import org.wildfly.security.tests.authauthz.runners.StandardSaslSuiteRunner;
import org.wildfly.security.tests.common.authauthz.HttpAuthenticationMechanism;
import org.wildfly.security.tests.common.authauthz.SaslAuthenticationMechanism;

/**
 * Base definition of the {@code Suite} of tests that will be used to run the authentication tests
 * against pre-configured realms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Suite
@SelectClasses(value = {
        StandardHttpSuiteRunner.class,
        StandardSaslSuiteRunner.class
})
public abstract class AbstractAuthenticationSuite {

    /*
     * General Constants
     */

    private static final String REALM_NAME = "TestRealm";

    // Test State
    // TODO - This will become the providers needed for testing.
    static Supplier<Provider[]> TEST_PROVIDERS = Security::getProviders;

    // New Test State
    private static volatile String providerName;
    private static volatile String realmType;
    private static volatile Supplier<SecurityRealm> securityRealmSupplier;
    private static volatile Supplier<Set<HttpAuthenticationMechanism>> supportedHttpAuthenticationMechanisms;
    private static volatile Supplier<Set<SaslAuthenticationMechanism>> supportedSaslAuthenticationMechanisms;

    /*
     * New Registration Methods
     */
    public static void register(String realmType, Supplier<SecurityRealm> securityRealmSupplier,
            Supplier<Set<HttpAuthenticationMechanism>> supportedHttpAuthenticationMechanisms,
            Supplier<Set<SaslAuthenticationMechanism>> supportedSaslAuthenticationMechanisms) {
        AbstractAuthenticationSuite.realmType = realmType;
        AbstractAuthenticationSuite.securityRealmSupplier = securityRealmSupplier;
        AbstractAuthenticationSuite.supportedHttpAuthenticationMechanisms = supportedHttpAuthenticationMechanisms;
        AbstractAuthenticationSuite.supportedSaslAuthenticationMechanisms = supportedSaslAuthenticationMechanisms;
    }

    public static String realmType() {
        return realmType;
    }

    public static boolean initialised() {
        return securityRealmSupplier != null;
    }

    public static SecurityDomain createSecurityDomain() {
        final SecurityDomain.Builder domainBuilder = SecurityDomain.builder();
        domainBuilder.addRealm(REALM_NAME, securityRealmSupplier.get()).build();
        domainBuilder.setDefaultRealmName(REALM_NAME);

        // Just grant login permission for now.
        domainBuilder.setPermissionMapper(
                (p, r) -> PermissionVerifier.from(new LoginPermission()));

        return domainBuilder.build();
    }

    public static Set<HttpAuthenticationMechanism> supportedHttpAuthenticationMechanisms() {
        return supportedHttpAuthenticationMechanisms == null ? Collections.emptySet()
                : supportedHttpAuthenticationMechanisms.get();
    }

    public static Set<SaslAuthenticationMechanism> supportedSaslAuthenticationMechanisms() {
        return supportedSaslAuthenticationMechanisms == null ? Collections.emptySet()
                : supportedSaslAuthenticationMechanisms.get();
    }

    @BeforeSuite
    static void registerProvider() {
        final WildFlyElytronProvider provider = new WildFlyElytronProvider();
        Security.addProvider(provider);
        providerName = provider.getName();
    }

    @AfterSuite
    public static void endSuite() throws IOException {
        //TODO - Can we handle all clean up on our own?
        System.out.printf("endSuite() called for mode='%s'\n", realmType);
        if (providerName != null) {
            Security.removeProvider(providerName);
            providerName = null;
        }
    }

    static Stream<IdentityDefinition> obtainTestIdentities() {
        // Register a lot of identities so each test can use it's own without
        // state being contaminated from other tests.
        List<IdentityDefinition> identities = new ArrayList<>(100);
        for (int i = 0 ; i < 100 ; i++) {
            identities.add(new IdentityDefinition(String.format("user%d", i),
                    String.format("password%d", i)));
        }

        return identities.stream();
    }

    record IdentityDefinition(String username, String password) {}
}
