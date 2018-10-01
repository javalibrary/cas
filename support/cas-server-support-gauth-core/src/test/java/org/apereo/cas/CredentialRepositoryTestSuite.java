package org.apereo.cas;

import org.apereo.cas.adaptors.gauth.credential.InMemoryGoogleAuthenticatorTokenCredentialRepositoryTests;
import org.apereo.cas.adaptors.gauth.credential.JsonGoogleAuthenticatorTokenCredentialRepositoryTests;
import org.apereo.cas.adaptors.gauth.credential.RestGoogleAuthenticatorTokenCredentialRepositoryTests;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * This is {@link CredentialRepositoryTestSuite}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    InMemoryGoogleAuthenticatorTokenCredentialRepositoryTests.class,
    JsonGoogleAuthenticatorTokenCredentialRepositoryTests.class,
    RestGoogleAuthenticatorTokenCredentialRepositoryTests.class
})
public class CredentialRepositoryTestSuite {
}
