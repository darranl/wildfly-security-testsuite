/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.tests.authauthz;

import static org.wildfly.security.tests.authauthz.AbstractAuthenticationSuite.obtainTestIdentities;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

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

        return password != null && username != null && Arrays.equals(passwordInModule, password);
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
}
