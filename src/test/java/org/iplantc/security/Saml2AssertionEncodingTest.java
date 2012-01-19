package org.iplantc.security;

import static org.junit.Assert.*;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;

import org.iplantc.saml.AssertionBuilder;
import org.iplantc.saml.AssertionEncrypter;
import org.iplantc.saml.Saml2Exception;
import org.iplantc.saml.util.KeyLoader;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.xml.security.utils.Base64;

public class Saml2AssertionEncodingTest {

    /**
     * A logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2AssertionEncodingTest.class);
    
    /**
     * The instance used for all of the tests.
     */
    private Saml2AssertionEncoding instance = null;
    
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
     * @param signingKeyAlias the alias of the key used to sign the assertion.
     * @return the signed assertion.
     * @throws Exception if an error occurs.
     */
    private Assertion createSignedAssertion(String signingKeyAlias) throws Exception {
        AssertionBuilder builder = new AssertionBuilder();
        builder.setSubject("nobody@iplantcollaborative.org");
        builder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        signAssertion(builder, signingKeyAlias);
        return builder.getAssertion();
    }

    /**
     * Encrypts an assertion.
     * 
     * @param assertion the assertion to encrypt.
     * @return the encrypted assertion.
     * @throws Exception if an error occurs.
     */
    private String encryptAssertion(Assertion assertion, String encryptingKeyAlias) throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        AssertionEncrypter encrypter = new AssertionEncrypter();
        encrypter.setPublicKey(keyLoader.loadCertificate(encryptingKeyAlias).getPublicKey());
        encrypter.setPublicKeyAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        encrypter.setSecretKeyAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
        return encrypter.encryptAssertion(assertion);
    }

    /**
     * Creates an assertion.
     * 
     * @param signingKeyAlias the alias for the key used to sign the assertion.
     * @param encryptingKeyAlias the alias for the key used to encrypt the assertion.
     * @return the base64 encoded assertion.
     * @throws Exception if an error occurs.
     */
    private String buildAssertion(String signingKeyAlias, String encryptingKeyAlias) throws Exception {
        Assertion assertion = createSignedAssertion(signingKeyAlias);
        return Base64.encode(encryptAssertion(assertion, encryptingKeyAlias).getBytes());
    }

    /**
     * Creates an assertion using the default signing and encrypting keys.
     *
     * @return the base64 encoded assertion.
     * @throws Exception if an error occurs.
     */
    private String buildAssertion() throws Exception {
        return buildAssertion("signing", "encrypting");
    }

    /**
     * Initializes each test.
     * @throws Exception if an error occurs.
     */
    @Before
    public void initialize() throws Exception {
        instance = new Saml2AssertionEncoding();
        instance.setKeyStorePath("src/test/resources/test.jceks");
        instance.setKeyStorePassword("changeit");
        instance.setKeyStoreType("JCEKS");
        instance.setKeyEncryptingKeyPairAlias("encrypting");
        instance.setKeyEncryptingKeyPairPassword("changeit");
        instance.setTrustedSigningCertificateAliases(Arrays.asList("signing", "signing2"));
        instance.afterPropertiesSet();
    }
    
    /**
     * Verifies that the initialization works when all of the required parameters are set.
     */
    @Test
    public void shouldInitialize() {
        logger.debug("Verifying that the initialization works when all required parameters are set...");
        assertNotNull(instance.getKeyStoreForTesting());
        assertNotNull(instance.getKeyEncryptingKeyPairForTesting());
        assertNotNull(instance.getTrustedSigningCertificatesForTesting());
        assertEquals(2, instance.getTrustedSigningCertificatesForTesting().size());
    }
    
    /**
     * Verifies that trying to set the keystore path to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyStorePath() {
        logger.debug("Verifying that trying to set the keystore path to null results in an exception...");
        instance.setKeyStorePath(null);
    }

    /**
     * Verifies that trying to set the keystore password to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyStorePassword() {
        logger.debug("Verifying that trying to set the keystore password to null results in an exception...");
        instance.setKeyStorePassword(null);
    }

    /**
     * Verifies that trying to set the keystore type to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyStoreType() {
        logger.debug("Verifying that trying to set the keystore type to null results in an exception...");
        instance.setKeyStoreType(null);
    }

    /**
     * Verifies that trying to set the key encrypting key pair alias to null causes an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyEncryptingKeyPairAlias() {
        logger.debug("Verifying that trying to set the key encrypting key pair alias to null causes an exception...");
        instance.setKeyEncryptingKeyPairAlias(null);
    }

    /**
     * Verifies that trying to set the key encrypting key pair password to null causes an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyEncryptingKeyPairPassword() {
        logger.debug("Verigying that an exception is thrown for a null key encrypting key pair password...");
        instance.setKeyEncryptingKeyPairPassword(null);
    }

    /**
     * Verifies that an exception is thrown for a null trusted signing certificate list.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullTrustedSigningCertificateAliasList() {
        logger.debug("Verifying that an exception is thrown for a null trusted signing certificate list...");
        instance.setTrustedSigningCertificateAliases(null);
    }

    /**
     * Verifies that an exception is thrown for an empty trusted signing certificate list.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowEmptyTrustedSigningCertificateAliasList() {
        logger.debug("Verifying that an exception is thrown for an empty trusted signing certificate list...");
        instance.setTrustedSigningCertificateAliases(new LinkedList<String>());
    }

    /**
     * Verifies that an assertion can be decoded.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldDecodeValidAssertion() throws Exception {
        logger.debug("Verifying that a valid assertion can be decoded...");
        String encodedAssertion = buildAssertion();
        assertNotNull(instance.decodeAssertion(encodedAssertion));
    }

    /**
     * Verifies that we get an exception for a null assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldGetExceptionForNullAssertion() throws Exception {
        logger.debug("Verifying that we get an exception for a null assertion...");
        instance.decodeAssertion(null);
    }

    /**
     * Verifies that we get an exception if the assertion can't be decoded.
     *
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldGetExceptionIfUnableToDecrypt() throws Exception {
        logger.debug("Verifying that we get an exception if the assertion can't be decrypted...");
        String encodedAssertion = buildAssertion("signing", "signing");
        instance.decodeAssertion(encodedAssertion);
    }
    
    /**
     * Verifies that we get an exception if the assertion signature can't be validated.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldGetExceptionIfUnableToValidateSignature() throws Exception {
        logger.debug("Verifying that we get an exception if the assertion signature can't be validated...");
        String encodedAssertion = buildAssertion("encrypting", "encrypting");
        instance.decodeAssertion(encodedAssertion);
    }

    /**
     * Verifies that we can accept multiple signing keys.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAcceptMultipleSigningKeys() throws Exception {
        logger.debug("Verifying that we can accept more than one signing key...");
        String encodedAssertion = buildAssertion("signing2", "encrypting");
        assertNotNull(instance.decodeAssertion(encodedAssertion));
    }
    
    /**
     * Verifies that we reject invalid base64 strings.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldRejectInvalidBase64() throws Exception {
        logger.debug("Verifying that we reject invalid base64 strings...");
        instance.decodeAssertion("Bleuh!  I vant you to throw an exception!");
    }
}
