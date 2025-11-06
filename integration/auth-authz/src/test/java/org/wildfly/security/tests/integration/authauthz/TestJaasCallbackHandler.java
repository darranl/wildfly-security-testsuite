/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.tests.integration.authauthz;

import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.security.Principal;

/**
 * A custom {@link CallbackHandler} used in the JAAS security realm tests. It implements the
 * {@code setSecurityInfo} method that has been historically used to populate custom handlers. Also, its {@code handle}
 * implementation will handle any kind of credential by calling {@code toString} and then {@code toCharArray} on the opaque
 * object.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class TestJaasCallbackHandler implements CallbackHandler {

    private Principal principal;
    private Evidence evidence;

    public TestJaasCallbackHandler() {
    }

    /**
     * Sets this handler's state.
     *
     * @param principal the principal being authenticated.
     * @param evidence the evidence being verified.
     */
    public void setSecurityInfo(final Principal principal, final Object evidence) {
        this.principal = principal;
        this.evidence = (Evidence) evidence;
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        if (callbacks == null) {
            throw new IllegalArgumentException("The callbacks argument cannot be null");
        }

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                if (principal != null)
                    nameCallback.setName(this.principal.getName());
            }
            else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                if (this.evidence instanceof PasswordGuessEvidence) {
                    passwordCallback.setPassword(((PasswordGuessEvidence) this.evidence).getGuess());
                }
            }
            else {
                throw new UnsupportedCallbackException(callback, "Unsupported callback");
            }
        }
    }
}
