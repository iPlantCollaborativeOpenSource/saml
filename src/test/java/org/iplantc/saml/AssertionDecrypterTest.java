package org.iplantc.saml;

import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.iplantc.saml.util.KeyLoader;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

/**
 * Verifies that we can successfully encrypt an assertion.
 * 
 * @author Dennis Roberts
 */
public class AssertionDecrypterTest {

    /**
     * The URL to associate with user attributes.
     */
    private static final String ATTRIBUTE_URL = "http://www.example.org/";

    /**
     * The builder used to build all of the assertions.
     */
    private AssertionBuilder builder;

    /**
     * The encrypter used to encrypt all of the assertions.
     */
    private AssertionEncrypter encrypter;

    /**
     * The decrypter used to decrypt all of the assertions.
     */
    private AssertionDecrypter decrypter;

    /**
     * The key pair used to encrypt the secret key.
     */
    private KeyPair encryptingKeyPair;
    
    /**
     * The key pair used to sign the assertion.
     */
    private KeyPair signingKeyPair;

    /**
     * The certificate used to sign the assertion.
     */
    private X509Certificate signingCertificate;
    
    /**
     * The private key used to sign the assertion.
     */
    private PrivateKey signingPrivateKey;

    /**
     * A logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(AssertionEncrypterTest.class);

    /**
     * Sets the secret key and the secret key algorithm.
     * 
     * @param secretKey the secret key to use for encryption.
     */
    private void setSecretKey() {
        encrypter.setSecretKey(null);
        encrypter.setSecretKeyAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
    }

    /**
     * Sets the public key and the public key algorithm.
     */
    private void setPublicKey() {
        encrypter.setPublicKey(encryptingKeyPair.getPublic());
        encrypter.setPublicKeyAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
    }

    /**
     * Builds an assertion for testing.
     * 
     * @throws Exception if an error occurs.
     */
    private void buildAssertion() throws Exception {
        builder.setSubject("nobody@iplantcollaborative.org");
        builder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        AttributeStatementBuilder attributeStatementBuilder = builder.addAttributeStatement();
        attributeStatementBuilder.addStringAttribute("someAttribute", ATTRIBUTE_URL, "someValue");
        attributeStatementBuilder.addStringAttribute("someOtherAttribute", ATTRIBUTE_URL, "someOtherValue");
    }

    /**
     * Encrypts an assertion.
     * 
     * @param secretKey the secret key used to encrypt the assertion.
     * @param signAssertion true if the assertion should be signed.
     * @return the assertion.
     * @throws MarshallingException if the assertion can't be marshalled or encrypted.
     */
    private String encryptAssertion() throws Exception {
        setPublicKey();
        setSecretKey();
        String encryptedAssertion = encrypter.encryptAssertion(builder.getAssertion());
        return encryptedAssertion;
    }

    /**
     * Decrypts a serialized assertion.
     * 
     * @param serializedAssertion the assertion to decrypt.
     * @return the decrypted assertion.
     * @throws Exception if the assertion can't be decrypted.
     */
    private Element decryptAssertion(String serializedAssertion) throws Exception {
        Assertion assertion = decrypter.decryptAssertion(serializedAssertion);
        return new Formatter().marshall(assertion);
    }

    /**
     * Initializes each test.
     * 
     * @throws Exception if an error occurs.
     */
    @Before
    public void initialize() throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        builder = new AssertionBuilder();
        encrypter = new AssertionEncrypter();
        encryptingKeyPair = keyLoader.loadKeyPair("encrypting");
        signingKeyPair = keyLoader.loadKeyPair("signing");
        signingCertificate = keyLoader.loadCertificate("signing");
        signingPrivateKey = signingKeyPair.getPrivate();
        decrypter = new AssertionDecrypter(encryptingKeyPair);
    }

    /**
     * Verifies that we can decrypt an assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldDecryptAssertion() throws Exception {
        logger.debug("Verifying that we can decrypt an encrypted assertion...");
        buildAssertion();
        Element expected = new Formatter().marshall(builder.getAssertion());
        String encryptedAssertion = encryptAssertion();
        Element actual = decryptAssertion(encryptedAssertion);
        assertXMLEqual(expected.getOwnerDocument(), actual.getOwnerDocument());
    }

    /**
     * Verifies that we can decrypt a signed assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldDecryptSignedAssertion() throws Exception {
        logger.debug("Verifying that we can decrypt a signed assertion...");
        buildAssertion();
        builder.signAssertion(signingCertificate, signingPrivateKey, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        Element expected = new Formatter().marshall(builder.getAssertion());
        String encryptedAssertion = encryptAssertion();
        Element actual = decryptAssertion(encryptedAssertion);
        assertXMLEqual(expected.getOwnerDocument(), actual.getOwnerDocument());
    }

    /**
     * Verifies that an IllegalArgumentException is thrown if we try to create a new decrypter with a null key
     * encrypting key pair.
     * 
     * @throws Excepton if an error occurs.
     */
    @Test(expected=IllegalArgumentException.class)
    public void shouldNotAllowDecrypterWithoutKeyPair() throws Exception {
        logger.debug("Verifying that we get an exception for a null key pair...");
        decrypter = new AssertionDecrypter(null);
    }
    
    /**
     * Verifies that an IllegalArgumentException is thrown if we try to decrypt a null assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=IllegalArgumentException.class)
    public void shouldNotAllowNullAssertion() throws Exception {
        logger.debug("Verifying that we get an exception for a null assertion...");
        decryptAssertion(null);
    }

    /**
     * Verifies that an exception is thrown if we try to decrypt an assertion containing invalid XML.
     *
     * @throws Exception if an error occurs.
     */
    @Test(expected=UnmarshallingException.class)
    public void shouldNotAllowInvalidXml() throws Exception {
        logger.debug("Verifying that we get an exception for invalid XML...");
        String phonyEncryptedAssertion = "Eh.  What's up, doc?";
        decryptAssertion(phonyEncryptedAssertion);
    }
    
    /**
     * Verifies that an exception is thrown if we try to decrypt an assertion with the wrong key pair.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=UnmarshallingException.class)
    public void shouldNotAllowIncorrectKey() throws Exception {
        logger.debug("Verifying that we get an exception for an incorrect key pair...");
        decrypter = new AssertionDecrypter(signingKeyPair);
        buildAssertion();
        new Formatter().marshall(builder.getAssertion());
        decryptAssertion(encryptAssertion());
    }
    
    /**
     * Verifies that wee get an UnmarshallingException if we try to decrypt an assertion that is not encrypted.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=UnmarshallingException.class)
    public void shouldNotAllowUnencryptedAssertion() throws Exception {
        logger.debug("Verifying that we get an exception for an unencrypted assertion...");
        buildAssertion();
        decryptAssertion(new Formatter().format(builder.getAssertion()));
    }
}
