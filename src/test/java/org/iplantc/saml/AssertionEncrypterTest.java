package org.iplantc.saml;

import static org.iplantc.saml.util.XMLFileAssert.*;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import org.iplantc.saml.util.KeyLoader;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xml.encryption.EncryptedKeyResolver;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Verifies that we can successfully encrypt an assertion.
 * 
 * @author Dennis Roberts
 */
public class AssertionEncrypterTest {
    
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
     * The secret key used to encrypt the assertions.
     */
    private SecretKey secretKey;

    /**
     * The key pair used to encrypt the secret key.
     */
    private KeyPair encryptingKeyPair;

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
    private void setSecretKey(SecretKey secretKey) {
        encrypter.setSecretKey(secretKey);
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
    private String encryptAssertion(SecretKey secretKey) throws MarshallingException {
        setPublicKey();
        setSecretKey(secretKey);
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
        EncryptedAssertion encryptedAssertion = unmarshallEncryptedAssertion(serializedAssertion);
        StaticKeyInfoCredentialResolver keyInfoResolver = buildKeyInfoResolver();
        EncryptedKeyResolver keyResolver = new EncryptedElementTypeEncryptedKeyResolver();
        Decrypter decrypter = new Decrypter(null, keyInfoResolver, keyResolver);
        Assertion assertion = decrypter.decrypt(encryptedAssertion);
        return new Formatter().marshall(assertion);
    }

    /**
     * Builds the static key info credential resolver used to resolve the key encryption key (that is, the public key
     * used to encrypt the secret key that was used to encrypt the actual assertion).
     * 
     * @return the key info credential resolver.
     */
    private StaticKeyInfoCredentialResolver buildKeyInfoResolver() {
        PublicKey publicKey = encryptingKeyPair.getPublic();
        PrivateKey privateKey = encryptingKeyPair.getPrivate();
        Credential credential = SecurityHelper.getSimpleCredential(publicKey, privateKey);
        StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
        return resolver;
    }

    /**
     * Unmarshalls a serialized encrypted assertion.
     * 
     * @param serializedAssertion the serialized encrypted assertion.
     * @return an encrypted assertion object.
     * @throws Exception if the assertion can't be parsed or unmarshalled.
     */
    private EncryptedAssertion unmarshallEncryptedAssertion(String serializedAssertion) throws Exception {
        BasicParserPool parser = new BasicParserPool();
        parser.setNamespaceAware(true);
        Document document = parser.parse(new StringReader(serializedAssertion));
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
        return (EncryptedAssertion) unmarshaller.unmarshall(document.getDocumentElement());
    }

    /**
     * Initializes all of the tests.
     * 
     * @throws Exception if an error occurs.
     */
    @Before
    public void initialize() throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        builder = new AssertionBuilder();
        encrypter = new AssertionEncrypter();
        secretKey = keyLoader.loadSecretKey("symmetric");
        encryptingKeyPair = keyLoader.loadKeyPair("encrypting");
        signingCertificate = keyLoader.loadCertificate("signing");
        signingPrivateKey = keyLoader.loadPrivateKey("signing");
    }

    /**
     * Verifies that we can successfully encrypt an assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldEncryptAssertion() throws Exception {
        logger.debug("Verifying that we can encrypt an assertion...");
        buildAssertion();
        Element expected = new Formatter().marshall(builder.getAssertion());
        String encryptedAssertion = encryptAssertion(secretKey);
        Element actual = decryptAssertion(encryptedAssertion);
        assertXMLEqual(expected.getOwnerDocument(), actual.getOwnerDocument());
    }

    /**
     * Verifies that we can encrypt an assertion using an automatically generated secret key.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldBeAbleToUseAutoGeneratedSecretKey() throws Exception {
        logger.debug("Verifying that we can encrypt an assertion using an automatically generated secret key...");
        buildAssertion();
        Element expected = new Formatter().marshall(builder.getAssertion());
        String encryptedAssertion = encryptAssertion(null);
        Element actual = decryptAssertion(encryptedAssertion);
        assertXMLEqual(expected.getOwnerDocument(), actual.getOwnerDocument());
    }

    /**
     * Verifies that we can encrypt a signed assertion.
     *
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldEncryptSignedAssertion() throws Exception {
        logger.debug("Verifying that we can encrypt a signed assertion...");
        buildAssertion();
        builder.signAssertion(signingCertificate, signingPrivateKey, SignatureConstants.ALGO_ID_SIGNATURE_RSA);
        Element expected = new Formatter().marshall(builder.getAssertion());
        String encryptedAssertion = encryptAssertion(secretKey);
        Element actual = decryptAssertion(encryptedAssertion);
        assertXMLEqual(expected.getOwnerDocument(), actual.getOwnerDocument());
    }

    /**
     * Verifies that we can't encrypt an assertion without a secret key algorithm.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=MarshallingException.class)
    public void shouldNotEncryptWithoutSecretKeyAlgorithm() throws Exception {
        logger.debug("Verifying that we can't encrypt an assertion without a secret key algorithm...");
        buildAssertion();
        setPublicKey();
        encrypter.encryptAssertion(builder.getAssertion());
    }

    /**
     * Verifies that we can't encrypt an assertion without a public key.
     *
     * @throws Exception if an error occurs.
     */
    @Test(expected=MarshallingException.class)
    public void shouldNotEncryptWithoutPublicKey() throws Exception {
        logger.debug("Verifying that we can't encrypt an assertion without a public key...");
        buildAssertion();
        setSecretKey(null);
        encrypter.setPublicKeyAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        encrypter.encryptAssertion(builder.getAssertion());
    }

    /**
     * Verifies that we can't encrypt an assertion without a public key algorithm.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=MarshallingException.class)
    public void shouldNotEncryptWithoutPublicKeyAlgorithm() throws Exception {
        logger.debug("Verifying that we can't encrypt an assertion without a public key algorithm...");
        buildAssertion();
        setSecretKey(null);
        encrypter.setPublicKey(encryptingKeyPair.getPublic());
        encrypter.encryptAssertion(builder.getAssertion());
    }
}
