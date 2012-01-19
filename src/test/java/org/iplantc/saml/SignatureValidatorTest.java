package org.iplantc.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.iplantc.saml.util.FileSlurper;
import org.iplantc.saml.util.KeyLoader;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unit tests for org.iplantc.saml.SignatureValidator.
 * 
 * @author Dennis Roberts
 */
public class SignatureValidatorTest {

    private final String[] TRUSTED_CREDENTIAL_NAMES = { "signing", "signing2" };

    private final Logger logger = LoggerFactory.getLogger(SignatureValidatorTest.class);

    private Formatter formatter;

    private FileSlurper slurper;

    private SignatureValidator validator;

    /**
     * Signs the assertion that is being built by the given assertion builder.
     * 
     * @param builder the builder that is being used to build the assertion.
     * @param keyAlias the alias of the key used to sign the assertion.
     * @throws Exception if an error occurs.
     */
    private void signAssertion(AssertionBuilder builder, String keyAlias) throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        X509Certificate certificate = keyLoader.loadCertificate(keyAlias);
        PrivateKey privateKey = keyLoader.loadPrivateKey(keyAlias);
        builder.signAssertion(certificate, privateKey, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    }

    /**
     * Creates a signed assertion.
     * 
     * @return the signed assertion.
     * @throws Exception if an error occurs.
     */

    private Assertion createSignedAssertion() throws Exception {
        return createSignedAssertion("signing");
    }
    
    /**
     * Creates an unsigned assertion.
     * 
     * @return the unsigned assertion.
     * @throws Exception if an error occurs.
     */
    private Assertion createUnsignedAssertion() throws Exception {
        return startAssertion().getAssertion();
    }
    
    /**
     * Creates a signed assertion.
     * 
     * @param signingKeyAlias the alias of the key used to sign the assertion.
     * @return the signed assertion.
     * @throws Exception if an error occurs.
     */
    private Assertion createSignedAssertion(String signingKeyAlias) throws Exception {
        AssertionBuilder builder = startAssertion();
        signAssertion(builder, signingKeyAlias);
        return builder.getAssertion();
    }

    /**
     * Starts creating an assertion.
     *
     * @return the assertion builder used to create the assertion.
     * @throws Saml2Exception if an error occurs.
     */
    private AssertionBuilder startAssertion() throws Saml2Exception {
        AssertionBuilder builder = new AssertionBuilder();
        builder.setSubject("nobody@iplantcollaborative.org");
        builder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        return builder;
    }

    /**
     * Encrypts an assertion.
     * 
     * @param assertion the assertion to encrypt.
     * @return the encrypted assertion.
     * @throws Exception if an error occurs.
     */
    private String encryptAssertion(Assertion assertion) throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        AssertionEncrypter encrypter = new AssertionEncrypter();
        encrypter.setPublicKey(keyLoader.loadCertificate("encrypting").getPublicKey());
        encrypter.setPublicKeyAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        encrypter.setSecretKeyAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
        return encrypter.encryptAssertion(assertion);
    }

    /**
     * Unmarshalls and decrypts a serialized encrypted assertion.
     * 
     * @param encryptedAssertion the assertion to decrypt.
     * @return the decrypted assertion.
     * @throws Exception if an error occurs.
     */
    private Assertion decryptAssertion(String encryptedAssertion) throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        KeyPair keyEncryptingKeyPair = keyLoader.loadKeyPair("encrypting");
        AssertionDecrypter decrypter = new AssertionDecrypter(keyEncryptingKeyPair);
        return decrypter.decryptAssertion(encryptedAssertion);
    }

    /**
     * Loads the trusted credentials from the keystore.
     * 
     * @throws Exception if an error occurs.
     */
    private void loadTrustedCredentials() throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        for (String name : TRUSTED_CREDENTIAL_NAMES) {
            X509Certificate certificate = keyLoader.loadCertificate(name);
            validator.addCredential(certificate);
        }
    }

    /**
     * Initializes each test.
     * 
     * @throws Exception if an error occurs.
     */
    @Before
    public void initialize() throws Exception {
        validator = new SignatureValidator();
        formatter = new Formatter();
        slurper = new FileSlurper();
        loadTrustedCredentials();
    }

    /**
     * Verifies that we can successfully add credentials to the signature validator.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAddCredentials() throws Exception {
        logger.debug("Verifying that we can add credentials to the signature validator...");
        assertEquals(2, validator.getCredentialCount());
    }

    /**
     * Verifies that we can successfully validate a signed assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldValidateSignedAssertion() throws Exception {
        logger.debug("Verifying that we can validate a signed assertion...");
        Assertion assertion = createSignedAssertion();
        assertTrue(validator.isValid(assertion));
    }

    /**
     * Verifies that we can successfully validate a signed assertion that has been unmarshalled from text.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldValidateUnmarshalledSignedAssertion() throws Exception {
        logger.debug("Verifying that we can validate a signed assertion that has been unmarshalled...");
        String xml = slurper.slurp("SignedSamlAssertion.xml");
        Assertion assertion = (Assertion) formatter.unmarshall(xml);
        assertTrue(validator.isValid(assertion));
    }

    /**
     * Verifies that an assertion that has been modified after it was signed is not validated.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldNotValidateModifiedSignedAssertion() throws Exception {
        logger.debug("Verifying that a signed assertion that has been modified is not validated...");
        String xml = slurper.slurp("BadSignedSamlAssertion.xml");
        Assertion assertion = (Assertion) formatter.unmarshall(xml);
        assertFalse(validator.isValid(assertion));
    }

    /**
     * Verifies that we can successfully validate an encrypted assertion that we have decrypted.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldValidateEncryptedSignedAssertion() throws Exception {
        logger.debug("Verifying that we can successfully validate an encrypted assertion that has been decrypted...");
        Assertion originalAssertion = createSignedAssertion();
        String encryptedAssertion = encryptAssertion(originalAssertion);
        Assertion assertion = decryptAssertion(encryptedAssertion);
        assertTrue(validator.isValid(assertion));
    }

    /**
     * Verifies that we can successfully validate assertions signed by multiple certificates.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAcceptMultipleCertificates() throws Exception {
        logger.debug("Verifying that we can validate assertions signed by multiple certificates...");
        Assertion firstAssertion = createSignedAssertion("signing");
        assertTrue(validator.isValid(firstAssertion));
        Assertion secondAssertion = createSignedAssertion("signing2");
        assertTrue(validator.isValid(secondAssertion));
    }

    /**
     * Verifies that an assertion signed by an unknown certificate is not validated.
     *
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldNotAcceptUnknownCertificate() throws Exception {
        logger.debug("Verifying that an assertion signed by an unknown certificate is not validated...");
        Assertion assertion = createSignedAssertion("encrypting");
        assertFalse(validator.isValid(assertion));
    }
    
    /**
     * Verifies that an unsigned assertion will be rejected.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldRejectUnsignedAssertion() throws Exception {
        logger.debug("Verifying that an unsigned assertion is not validated...");
        Assertion assertion = createUnsignedAssertion();
        assertFalse(validator.isValid(assertion));
    }
}
