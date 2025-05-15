/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.authauthz;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Base definition of the {@code Suite} of tests that will be used to run the authentication tests
 * against pre-configured realms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@Suite
@SelectClasses(value = {AuthPermutationsSuiteRunner.class,
        ParamAuthPermutationsSuiteRunner.class,
        DynamicAuthPermutationsSuiteRunner.class})
public abstract class AbstractAuthenticationSuite {

    // TODO - This will become the providers needed for testing.
    static final Supplier<Provider[]> TEST_PROVIDERS = Security::getProviders;

    private static final String REALM_NAME = "TestRealm";

    private static String mode = "";

    @AfterSuite
    public static void endSuite() {
        //TODO - Can we handle all clean up on our own?
        System.out.printf("endSuite() called for mode='%s'\n", mode);
    }

    static void setMode(final String mode) {
        AbstractAuthenticationSuite.mode = mode;
    }

    static String getMode() {
        return mode;
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
