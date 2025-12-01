/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.tests.integration.authauthz;

import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.wildfly.common.Assert;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.ModifiableRealmIdentityIterator;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.PasswordSpec;

/**
 * A custom modifiable security realm {@link ModifiableSecurityRealm} backed by a {@link Map}.
 */
public class TestCustomSecurityRealm implements ModifiableSecurityRealm {

    private final Map<String, char[]> identities = new HashMap<>();

    public TestCustomSecurityRealm() {
        obtainTestIdentities().forEach(identity -> {
            this.identities.put(identity.username(), identity.password().toCharArray());
        });
    }

    @Override
    public ModifiableRealmIdentityIterator getRealmIdentityIterator() throws RealmUnavailableException {
        return ModifiableRealmIdentityIterator.emptyIterator();
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
            AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {

        Assert.checkNotNullParam("credentialType", credentialType);
        return PasswordCredential.class.isAssignableFrom(credentialType) &&
                (algorithmName == null || algorithmName.equals(ALGORITHM_CLEAR) || algorithmName.equals(ALGORITHM_DIGEST_MD5)) &&
                (parameterSpec == null || parameterSpec instanceof DigestPasswordAlgorithmSpec)
                ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> type, String string) throws RealmUnavailableException {
        return PasswordGuessEvidence.class.isAssignableFrom(type) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
        NamePrincipal namePrincipal = NamePrincipal.from(principal);

        if (namePrincipal == null || !identities.containsKey(namePrincipal.getName())) {
            return RealmIdentity.NON_EXISTENT;
        }

        return new RealmIdentity() {

            @Override
            public Principal getRealmIdentityPrincipal() {
                return namePrincipal;
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
                    AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {

                return TestCustomSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
                return getCredential(credentialType, null, null);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
                return getCredential(credentialType, algorithmName, null);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                if (!identities.containsKey(namePrincipal.getName())) {
                    return null;
                }
                try {
                    final PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
                    final PasswordSpec passwordSpec = new ClearPasswordSpec(identities.get(namePrincipal.getName()));
                    return credentialType.cast(new PasswordCredential(passwordFactory.generatePassword(passwordSpec)));
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
                    throws RealmUnavailableException {

                return TestCustomSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName);
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                if (!identities.containsKey(namePrincipal.getName()) || !(evidence instanceof PasswordGuessEvidence)) {
                    return false;
                }

                final char[] guess = ((PasswordGuessEvidence) evidence).getGuess();

                try {
                    final PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
                    final PasswordSpec passwordSpec = new ClearPasswordSpec(identities.get(namePrincipal.getName()));
                    final Password actualPassword = passwordFactory.generatePassword(passwordSpec);
                    return passwordFactory.verify(actualPassword, guess);
                } catch (InvalidKeySpecException | InvalidKeyException | IllegalStateException | NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return true;
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                return AuthorizationIdentity.basicIdentity(new MapAttributes(
                        Collections.singletonMap("groups", Collections.unmodifiableSet(Set.of("admin")))));
            }
        };
    }

    // TODO move this to common module together with methods in AbstractAuthenticationSuite classes
    static Stream<TestCustomSecurityRealm.IdentityDefinition> obtainTestIdentities() {
        List<TestCustomSecurityRealm.IdentityDefinition> identities = new ArrayList<>(100);
        for (int i = 1 ; i < 100 ; i++) {
            identities.add(new TestCustomSecurityRealm.IdentityDefinition(String.format("user%d", i),
                    String.format("password%d", i)));
        }

        return identities.stream();
    }

    record IdentityDefinition(String username, String password) {}
}
