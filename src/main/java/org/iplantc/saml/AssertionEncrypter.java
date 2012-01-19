package org.iplantc.saml;

import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides a simple way to encrypt SAML assertions.
 *
 * @author Dennis Roberts
 * 
 * TODO modify class so that it only throws descendants of Saml2Exception.
 * TODO if necessary, modify class so that it can create different encrypted assertion formats.
 */
public class AssertionEncrypter {

    /**
     * The logger to use for debugging and informational messages.
     */
    Logger logger = LoggerFactory.getLogger(AssertionEncrypter.class);

    /**
     * The secret key used to encrypt the assertion.
     */
    private SecretKey secretKey;

    /**
     * The algorithm used to generate the secret key.
     */
    private String secretKeyAlgorithm;

    /**
     * The public key used to encrypt the secret key.
     */
    private PublicKey publicKey;

    /**
     * The algorithm used to create the public key.
     */
    private String publicKeyAlgorithm;

    /**
     * Creates a new encrypter.
     */
    public AssertionEncrypter() {
        Bootstrap.bootstrap();
        secretKey = null;
        secretKeyAlgorithm = null;
        publicKey = null;
        publicKeyAlgorithm = null;
    }

    /**
     * The setter for the secretKey property.
     * 
     * @param secretKey the secret key.
     */
    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * The setter for the secretKeyAlgorithm property.
     * 
     * @param secretKeyAlgorithm the secret key algorithm.
     */
    public void setSecretKeyAlgorithm(String secretKeyAlgorithm) {
        this.secretKeyAlgorithm = secretKeyAlgorithm;
    }

    /**
     * The setter for the publicKey property.
     * 
     * @param publicKey the public key.
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * The setter for the publicKeyAlgorithm property.
     * 
     * @param publicKeyAlgorithm the public key algorithm.
     */
    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    /**
     * Encrypts a SAML assertion.
     * 
     * @param assertion the assertion to encrypt.
     * @return the encrypted assertion as a string.
     * @throws MarshallingException if the assertion can't be encrypted or converted to a string.
     */
    public String encryptAssertion(Assertion assertion) throws MarshallingException {
        EncryptionParameters encryptionParameters = buildEncryptionParameters();
        KeyEncryptionParameters keyEncryptionParameters = buildKeyEncryptionParameters();
        Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
        EncryptedAssertion encryptedAssertion = getEncryptedAssertion(encrypter, assertion);
        return new Formatter().format(encryptedAssertion);
    }

    /**
     * Builds the encryption parameters.
     * 
     * @return the encryption parameters.
     */
    private EncryptionParameters buildEncryptionParameters() throws MarshallingException {
        validateEncryptionParameters();
        EncryptionParameters parameters = new EncryptionParameters();
        if (secretKey != null) {
            parameters.setEncryptionCredential(SecurityHelper.getSimpleCredential(secretKey));
        }
        parameters.setAlgorithm(secretKeyAlgorithm);
        return parameters;
    }

    /**
     * Validates the encryption parameters.
     * 
     * @throws MarshallingException if the parameters are invalid.
     */
    private void validateEncryptionParameters() throws MarshallingException {
        if (secretKeyAlgorithm == null) {
            throwMarshallingException("attempt to encrypt an assertion without a secret key algorithm");
        }
    }

    /**
     * Builds the key encryption parameters.
     * 
     * @return the key encryption parameters.
     * @throws MarshallingException if the parameters are invalid.
     */
    private KeyEncryptionParameters buildKeyEncryptionParameters() throws MarshallingException {
        validateKeyEncryptionParameters();
        KeyEncryptionParameters parameters = new KeyEncryptionParameters();
        Credential credential = SecurityHelper.getSimpleCredential(publicKey, null);
        parameters.setEncryptionCredential(credential);
        parameters.setAlgorithm(publicKeyAlgorithm);
        parameters.setKeyInfoGenerator(getKeyInfoGenerator(credential));
        return parameters;
    }

    /**
     * Validates the key encryption parameters.
     * 
     * @throws MarshallingException if the parameters are invalid.
     */
    private void validateKeyEncryptionParameters() throws MarshallingException {
        if (publicKey == null) {
            throwMarshallingException("attempt to encrypt an assertion without a public key");
        }
        if (publicKeyAlgorithm == null) {
            throwMarshallingException("attempt to encrypt an assertion without a public key algorithm");
        }
    }

    /**
     * Creates a new key info generator.
     * 
     * @param credential the credential to associate with the key info generator.
     * @return the new key info generator.
     */
    private KeyInfoGenerator getKeyInfoGenerator(Credential credential) {
        return Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager().getDefaultManager()
                .getFactory(credential).newInstance();
    }

    /**
     * Encrypts an assertion.
     * 
     * @param encrypter the encrypter used to encrypt the assertion.
     * @param assertion the assertion to encrypt.
     * @return the encrypted assertion.
     * @throws MarshallingException if the assertion can't be encrypted.
     */
    private EncryptedAssertion getEncryptedAssertion(Encrypter encrypter, Assertion assertion)
            throws MarshallingException
    {
        try {
            return encrypter.encrypt(assertion);
        }
        catch (EncryptionException e) {
            String msg = "unable to encrypt the assertion";
            logger.error(msg, e);
            throw new MarshallingException(msg, e);
        }
    }

    /**
     * Throws a MarshallingException. This is just a time saver for the common case where we have to throw a
     * MarshallingException with just a message.
     * 
     * @param msg the message to log and associate with the exception.
     * @throws MarshallingException always.
     */
    private void throwMarshallingException(String msg) throws MarshallingException {
        logger.error(msg);
        throw new MarshallingException(msg);
    }
}
