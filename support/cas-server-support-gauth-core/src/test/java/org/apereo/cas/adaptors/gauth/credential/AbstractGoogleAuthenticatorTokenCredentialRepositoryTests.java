package org.apereo.cas.adaptors.gauth.credential;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.util.CollectionUtils;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.IGoogleAuthenticator;
import lombok.Getter;
import lombok.val;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;

import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link AbstractGoogleAuthenticatorTokenCredentialRepositoryTests}.
 *
 * @author Timur Duehr
 * @since 6.0.0
 */
@Getter
public abstract class AbstractGoogleAuthenticatorTokenCredentialRepositoryTests {
    @ClassRule
    public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();
    public static final String CASUSER = "casusergauth";
    public static final String PLAIN_SECRET = "plain_secret";

    @Rule
    public final SpringMethodRule springMethodRule = new SpringMethodRule();

    private IGoogleAuthenticator google;

    @Mock
    private CipherExecutor<String, String> cipherExecutor;

    private Map<Pair<String, String>, OneTimeTokenAccount> accountHashMap = new LinkedHashMap<>();

    public OneTimeTokenAccount getAccount(final String testName, final String username) {
        return accountHashMap.computeIfAbsent(Pair.of(testName, username), pair -> getRepository(pair.getLeft()).create(pair.getRight()));
    }

    @Before
    public void initialize() {
        val bldr = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        this.google = new GoogleAuthenticator(bldr.build());
    }

    @Test
    public void verifyCreate() {
        val acct = getAccount("verifyCreate", CASUSER);
        assertNotNull(acct);
    }

    @Test
    public void verifySaveAndUpdate() {
        getRepository().save(CASUSER, "secret", 111222, CollectionUtils.wrapList(1, 2, 3, 4, 5, 6));
        var s = getRepository().get(CASUSER);
        assertNotNull(s.getRegistrationDate());
        assertEquals(111222, s.getValidationCode());
        assertEquals("secret", s.getSecretKey());
        s.setSecretKey("newSecret");
        s.setValidationCode(999666);
        getRepository().update(s);
        s = getRepository().get(CASUSER);
        assertEquals(999666, s.getValidationCode());
        assertEquals("newSecret", s.getSecretKey());
    }

    @Test
    public void verifyGet() {
        val repo = getRepository("verifyGet");
        val acct = repo.get(CASUSER);
        assertNull(acct);
        val acct2 = getAccount("verifyGet", CASUSER);
        repo.save(acct2.getUsername(), acct2.getSecretKey(), acct2.getValidationCode(), acct2.getScratchCodes());
        val acct3 = repo.get(CASUSER);
        assertEquals(acct2.getUsername(), acct3.getUsername());
        assertEquals(acct2.getValidationCode(), acct3.getValidationCode());
        assertEquals(acct2.getSecretKey(), acct3.getSecretKey());
        assertEquals(acct2.getScratchCodes(), acct3.getScratchCodes());
        assertEquals(acct2.getRegistrationDate().truncatedTo(ChronoUnit.SECONDS), acct3.getRegistrationDate().withFixedOffsetZone().truncatedTo(ChronoUnit.SECONDS));
    }

    @Test
    public void verifyGetWithDecodedSecret() {
        // given
        when(cipherExecutor.encode(PLAIN_SECRET)).thenReturn("abc321");
        when(cipherExecutor.decode("abc321")).thenReturn(PLAIN_SECRET);
        val repo = getRepository("verifyGetWithDecodedSecret");
        var acct = repo.create(CASUSER);
        acct.setSecretKey(PLAIN_SECRET);
        repo.save(acct.getUsername(), acct.getSecretKey(), acct.getValidationCode(), acct.getScratchCodes());

        // when
        acct = repo.get(CASUSER);

        // then
        assertEquals(PLAIN_SECRET, acct.getSecretKey());
    }

    public OneTimeTokenCredentialRepository getRepository(final String testName) {
        return getRepository();
    };

    public abstract OneTimeTokenCredentialRepository getRepository();
}
