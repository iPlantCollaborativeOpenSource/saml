package org.iplantc.saml;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xml.encryption.EncryptedKeyResolver;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

/**
 * Provides a simplified way to decrypt SAML assertions that are formatted in the way we want them to be.
 * 
 * @author Dennis Roberts
 * 
 * TODO modify class so that it only throws descendants of Saml2Exception.
 * TODO if necessary, modify class to handle different encrypted assertion formats.
 */
public class AssertionDecrypter {

    /**
     * The key pair that was used to encrypt the symmetric key that was used to encrypt the assertion.
     */
    private KeyPair keyEncryptingKeyPair;

    /**
     * The decrypter that will be used to decrypt the assertion.
     */
    private Decrypter decrypter;

    /**
     * The logger to use for error and informational messages.
     */
    private final Logger logger = LoggerFactory.getLogger(AssertionDecrypter.class);

    /**
     * Creates a new decrypter that can be used to decrypt assertions.
     * 
     * @param keyEncryptingKeyPair they key pair that is used to encrypt symmetric keys.
     */
    public AssertionDecrypter(KeyPair keyEncryptingKeyPair) {
        Bootstrap.bootstrap();
        validateKeyEncryptingKeyPair(keyEncryptingKeyPair);
        assert keyEncryptingKeyPair != null;
        this.keyEncryptingKeyPair = keyEncryptingKeyPair;
        this.decrypter = createDecrypter();
    }

    /**
     * Validates the key encrypting key pair that was passed ot the constructor.
     * 
     * @param keyEncryptingKeyPair the key pair to validate.
     */
    private void validateKeyEncryptingKeyPair(KeyPair keyEncryptingKeyPair) {
        if (keyEncryptingKeyPair == null) {
            String msg = "a key pair is required to create a decrypter";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Cretes the decrypter.
     * 
     * @return the decrypter.
     */
    private Decrypter createDecrypter() {
        StaticKeyInfoCredentialResolver keyInfoResolver = buildKeyInfoResolver();
        EncryptedKeyResolver keyResolver = new EncryptedElementTypeEncryptedKeyResolver();
        Decrypter decrypter = new Decrypter(null, keyInfoResolver, keyResolver);
        decrypter.setRootInNewDocument(true);
        return decrypter;
    }

    /**
     * Builds the static key info credential resolver used to resolve the key encryption key.
     * 
     * @return the key info credential resolver.
     */
    private StaticKeyInfoCredentialResolver buildKeyInfoResolver() {
        PublicKey publicKey = keyEncryptingKeyPair.getPublic();
        PrivateKey privateKey = keyEncryptingKeyPair.getPrivate();
        Credential credential = SecurityHelper.getSimpleCredential(publicKey, privateKey);
        StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
        return resolver;
    }

    /**
     * Decrypts a serialized assertion.
     * 
     * @param serializedAssertion the serialized assertion to decrypt.
     * @return the decrypted assrtion.
     * @throws UnmarshallingException if the assertion can't be parsed, unmarshalled or decrypted.
     */
    public Assertion decryptAssertion(String serializedAssertion) throws UnmarshallingException {
        validateSerializedAssertion(serializedAssertion);
        EncryptedAssertion encryptedAssertion = unmarshallEncryptedAssertion(serializedAssertion);
        try {
            return decrypter.decrypt(encryptedAssertion);
        }
        catch (Exception e) {
            String msg = "unable to decrypt the encrypted assertion";
            logger.error(msg, e);
            throw new UnmarshallingException(e);
        }
    }

    /**
     * Validates a serialized assertion.
     *
     * @param serializedAssertion the assertion to validate.
     */
    private void validateSerializedAssertion(String serializedAssertion) {
        if (serializedAssertion == null) {
            String msg = "no assertion to decrypt";
            logger.error(msg);
            throw new IllegalArgumentException(msg);
        }
    }
    
    /**
     * Unmarshalls a serialized encrypted assertion.
     * 
     * @param serializedAssertion the serialized encrypted assertion.
     * @return an encrypted assertion object.
     * @throws UnmarshallingException if the assertion can't be parsed or unmarshalled.
     */
    private EncryptedAssertion unmarshallEncryptedAssertion(String serializedAssertion) throws UnmarshallingException {
        try {
            BasicParserPool parser = new BasicParserPool();
            parser.setNamespaceAware(true);
            Document document = parser.parse(new StringReader(serializedAssertion));
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
            return (EncryptedAssertion) unmarshaller.unmarshall(document.getDocumentElement());
        }
        catch (ClassCastException e) {
            String msg = "the assertion does not appear to be encrypted";
            logger.error(msg, e);
            throw new UnmarshallingException(msg, e);
        }
        catch (XMLParserException e) {
            String msg = "unable to parse the encrypted assertion";
            logger.error(msg, e);
            throw new UnmarshallingException(msg, e);
        }
    }
}
