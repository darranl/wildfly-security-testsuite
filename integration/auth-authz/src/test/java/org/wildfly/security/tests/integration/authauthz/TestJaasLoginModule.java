/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.tests.integration.authauthz;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import org.wildfly.security.auth.principal.NamePrincipal;

/**
 * A JAAS {@link LoginModule} backed by a {@link Map}.
 * Users are initialized from {@link AbstractAuthenticationSuite#obtainTestIdentities}.
 */
public class TestJaasLoginModule implements LoginModule {

    private final Map<String, char[]> identities = new HashMap<>();
    private Subject subject;
    private CallbackHandler callbackHandler;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        obtainTestIdentities().forEach(identity -> {
            this.identities.put(identity.username(), identity.password().toCharArray());
        });
    }

    @Override
    public boolean login() throws LoginException {
        NameCallback nameCallback = new NameCallback("Username");
        PasswordCallback passwordCallback = new PasswordCallback("Password", false);
        Callback[] callbacks = new Callback[] {nameCallback, passwordCallback};
        try {
            this.callbackHandler.handle(callbacks);
        } catch(UnsupportedCallbackException | IOException e) {
            throw new LoginException("Callback handling failed: " + e.getMessage());
        }

        String username = nameCallback.getName();
        char[] password = passwordCallback.getPassword();
        char[] passwordInModule = this.identities.get(username);

        boolean success = password != null && username != null && Arrays.equals(passwordInModule, password);
        if (success) {
            this.subject.getPrincipals().add(new NamePrincipal(username));
            this.subject.getPrincipals().add(new groups("admin"));
        }
        return success;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        this.subject.getPrincipals().clear();
        return true;
    }

    // TODO move this to common module together with methods in AbstractAuthenticationSuite classes
    static Stream<TestJaasLoginModule.IdentityDefinition> obtainTestIdentities() {
        List<TestJaasLoginModule.IdentityDefinition> identities = new ArrayList<>(100);
        for (int i = 1 ; i < 100 ; i++) {
            identities.add(new TestJaasLoginModule.IdentityDefinition(String.format("user%d", i),
                    String.format("password%d", i)));
        }

        return identities.stream();
    }

    record IdentityDefinition(String username, String password) {}

    // Elytron is case sensitive and the default mapper is from "groups" (to roles)
    private static class groups implements Principal {

        private final String name;

        groups(final String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return this.name;
        }
    }
}
