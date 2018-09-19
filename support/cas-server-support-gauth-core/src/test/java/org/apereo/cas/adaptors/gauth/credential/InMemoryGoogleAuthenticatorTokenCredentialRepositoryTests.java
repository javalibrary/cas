package org.apereo.cas.adaptors.gauth.credential;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.adaptors.gauth.repository.credentials.InMemoryGoogleAuthenticatorTokenCredentialRepository;
import org.apereo.cas.config.CasCoreUtilConfiguration;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;

import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;


/**
 * This is {@link InMemoryGoogleAuthenticatorTokenCredentialRepositoryTests}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@SpringBootTest(classes = {
    AopAutoConfiguration.class,
    CasCoreUtilConfiguration.class
})
public class InMemoryGoogleAuthenticatorTokenCredentialRepositoryTests extends AbstractGoogleAuthenticatorTokenCredentialRepositoryTests {
    @Override
    public OneTimeTokenCredentialRepository getRepository() {
        return new InMemoryGoogleAuthenticatorTokenCredentialRepository(CipherExecutor.noOpOfStringToString(), getGoogle());
    }
}
