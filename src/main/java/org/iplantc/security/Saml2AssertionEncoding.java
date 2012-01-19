package org.iplantc.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.iplantc.saml.AssertionDecrypter;
import org.iplantc.saml.Saml2Exception;
import org.iplantc.saml.SignatureValidator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

/**
 * Handles the decoding of SAML assertions. For the purposes of this class, decoding involves decoding a base64 string
 * representing an assertion, unmarshalling the resulting XML string, decrypting the unmarshalled object and, finally,
 * validating the signature on the assertion.
 * 
 * @author Dennis Roberts
 * 
 */
public class Saml2AssertionEncoding {

    /**
     * A logger for error and informational messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2AssertionEncoding.class);

    /**
     * The path to the keystore containing the cryptography keys that we have to use.
     */
    private String keyStorePath = null;

    /**
     * The password to use to access the keystore.
     */
    private String keyStorePassword = null;

    /**
     * The type of keystore we're dealing with (for example, JKS or JCEKS). The default is JKS.
     */
    private String keyStoreType = "JKS";

    /**
     * The alias for the key encrypting key pair.
     */
    private String keyEncryptingKeyPairAlias = null;

    /**
     * The password used to access the key encrypting key pair.
     */
    private String keyEncryptingKeyPairPassword = null;

    /**
     * The aliases used to refer to the trusted signing certificates.
     */
    private List<String> trustedSigningCertificateAliases = null;

    /**
     * The keystore containing our key encrypting key pair and all of the trusted signing certificates.
     */
    private KeyStore keystore = null;

    /**
     * The key pair used to encrypt the secret key used to encrypt the SAML assertion.
     */
    private KeyPair keyEncryptingKeyPair = null;

    /**
     * The list of trusted signing certificates.
     */
    private List<X509Certificate> trustedSigningCertificates = null;

    /**
     * Used to decrypt incoming SAML assertions.
     */
    private AssertionDecrypter assertionDecrypter = null;

    /**
     * Used to validate the signatures on incoming SAML assertions.
     */
    private SignatureValidator signatureValidator = null;

    /**
     * Queso apestoso: indicates whether or not initialization is complete.
     */
    private boolean initialized = false;

    /**
     * Verifies that all required properties have been set.
     * 
     * @throws Exception if any required property hasn't been set.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(keyStorePath, "a keystore path is required");
        Assert.notNull(keyStorePassword, "a keystore password is required");
        Assert.notNull(keyEncryptingKeyPairAlias, "a key encrypting key pair alias is required");
        Assert.notNull(keyEncryptingKeyPairPassword, "a key encrypting key pair password is required");
        Assert.notNull(trustedSigningCertificateAliases, "a list of trusted signing certificate aliases is required");
        Assert.notEmpty(trustedSigningCertificateAliases, "at least one trusted signing certificate is required");
        loadKeyStore();
        keyEncryptingKeyPair = loadKeyPair(keyEncryptingKeyPairAlias, keyEncryptingKeyPairPassword);
        loadTrustedSigningCertificates();
        assertionDecrypter = new AssertionDecrypter(keyEncryptingKeyPair);
        createSignatureValidator();
        initialized = true;
    }

    /**
     * Loads the keystore.
     * 
     * @throws IOException if an I/O error occurs.
     * @throws GeneralSecurityException if the keystore can't be loaded.
     */
    private void loadKeyStore() throws IOException, GeneralSecurityException {
        InputStream in = null;
        try {
            keystore = KeyStore.getInstance(keyStoreType);
            in = getInputStream(keyStorePath);
            keystore.load(in, keyStorePassword.toCharArray());
        }
        finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /**
     * Gets the input stream for the keystore, which may be relative to the current working directory or relative to
     * any location in the classpath.
     * 
     * @param path the relative path to the keystore.
     * @return an input stream that can be used to read the keystore.
     * @throws FileNotFoundException if the keystore can't be found.
     */
    private InputStream getInputStream(String path) throws FileNotFoundException {
        File file = new File(path);
        if (file.exists()) {
            return new FileInputStream(file);
        }
        else {
            InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
            if (in == null) {
                throw new FileNotFoundException(path);
            }
            return in;
        }
    }

    /**
     * Loads a key pair from the keystore.
     * 
     * @param alias the alias that refers to the keystore.
     * @param password the password used to access the private key.
     * @return the key pair.
     * @throws GeneralSecurityException if the key pair can't be loaded.
     */
    private KeyPair loadKeyPair(String alias, String password) throws GeneralSecurityException {
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
        X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
        logger.debug("loaded a certificate: {}", certificate);
        PublicKey publicKey = certificate.getPublicKey();
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Loads the list of trusted signing certificates from the keystore.
     * 
     * @throws GeneralSecurityException if any of the certificates can't be loaded.
     */
    private void loadTrustedSigningCertificates() throws GeneralSecurityException {
        trustedSigningCertificates = new LinkedList<X509Certificate>();
        for (String alias : trustedSigningCertificateAliases) {
            trustedSigningCertificates.add((X509Certificate) keystore.getCertificate(alias));
        }
    }

    /**
     * Creates the signature validator and adds the trusted signing certificates to it.
     */
    private void createSignatureValidator() {
        signatureValidator = new SignatureValidator();
        for (X509Certificate certificate : trustedSigningCertificates) {
            signatureValidator.addCredential(certificate);
        }
    }

    /**
     * Setter for the keyStorePath property.
     * 
     * @param keyStorePath the path to the keystore containing our cryptography keys.
     */
    public void setKeyStorePath(String keyStorePath) {
        Assert.notNull(keyStorePath, "a keystore path is required");
        this.keyStorePath = keyStorePath;
    }
    
    /**
     * Getter for the keyStorePathProperty.
     * 
     * @return the path to the keystore containing our cryptography keys.
     */
    public String getKeyStorePath() {
        return keyStorePath;
    }

    /**
     * Setter for the keyStorePassword property.
     * 
     * @param keyStorePassword the password used to access the keystore.
     */
    public void setKeyStorePassword(String keyStorePassword) {
        Assert.notNull(keyStorePassword, "a keystore password is required");
        this.keyStorePassword = keyStorePassword;
    }

    /**
     * Getter for the keyStorePassword property.
     * 
     * @return the password used to access the keystore.
     */
    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    /**
     * Setter for the keyStoreType property.
     * 
     * @param keyStoreType the type of keystore that we're dealing with (for example, JKS or JCEKS). JKS is the default.
     */
    public void setKeyStoreType(String keyStoreType) {
        Assert.notNull(keyStoreType, "a keystore type is required");
        this.keyStoreType = keyStoreType;
    }
    
    /**
     * Getter for the keyStoreType property.
     * 
     * @return the type of keystore that we're dealing with (for example, JKS or JCEKS).
     */
    public String getKeyStoreType() {
        return keyStoreType;
    }

    /**
     * Setter for the keyEncryptingKeyPairAlias property.
     * 
     * @param alias the alias used to refer to the key encrypting key pair in the keystore.
     */
    public void setKeyEncryptingKeyPairAlias(String alias) {
        Assert.notNull(alias, "an alias is required");
        keyEncryptingKeyPairAlias = alias;
    }

    /**
     * Getter for the keyEncryptingKeyPairAlias property.
     * 
     * @return the alias used to refer to the key encrypting key pair in the keystore.
     */
    public String getKeyEncryptingKeyPairAlias() {
        return keyEncryptingKeyPairAlias;
    }
    
    /**
     * Setter for the keyEncryptingKeyPairPassword property.
     * 
     * @param password the password to use to access the key encrypting key pair.
     */
    public void setKeyEncryptingKeyPairPassword(String password) {
        Assert.notNull(password, "a password is required");
        keyEncryptingKeyPairPassword = password;
    }

    /**
     * Getter for the keyEncryptingKeyPairPassword property.
     * 
     * @return the password used to access the key encrypting key pair.
     */
    public String getKeyEncryptingKeyPairPassword() {
        return keyEncryptingKeyPairPassword;
    }
    
    /**
     * Setter for the trustedSigningCertificateAliases property.
     * 
     * @param aliases the list of aliases used to reference signing certificates that we trust.
     */
    public void setTrustedSigningCertificateAliases(List<String> aliases) {
        Assert.notNull(aliases, "a list of aliases is required");
        Assert.notEmpty(aliases, "at least one alias is required");
        trustedSigningCertificateAliases = aliases;
    }

    /**
     * Getter for the trustedSigningCertificateAliases property.
     * 
     * @return the list of aliases used to reference signing certificates that we trust.
     */
    public List<String> getTrustedSigningCertificateAliases() {
        return Collections.unmodifiableList(trustedSigningCertificateAliases);
    }
    
    /**
     * Getter for the keystore property. This method is meant to be used only for testing.
     * 
     * @return the keystore.
     */
    public KeyStore getKeyStoreForTesting() {
        return keystore;
    }

    /**
     * Getter for the keyEncryptingKeyPair property. This method is meant to be used only for testing.
     * 
     * @return the key encrypting key pair.
     */
    public KeyPair getKeyEncryptingKeyPairForTesting() {
        return keyEncryptingKeyPair;
    }

    /**
     * Getter for the trustedSigningCertificates property. This method is meant to be used only for testing.
     * 
     * @return the list of trusted signing certificates.
     */
    public List<X509Certificate> getTrustedSigningCertificatesForTesting() {
        return trustedSigningCertificates;
    }

    /**
     * Decodes the given assertion.
     * 
     * @param encodedAssertion the assertion to decode.
     * @return the decoded assertion.
     * @throws Saml2Exception if the assertion can't be decoded.
     */
    public Assertion decodeAssertion(String encodedAssertion) throws Saml2Exception {
        initialize();
        validateEncodedAssertion(encodedAssertion);
        String encrypted = decodeBase64(encodedAssertion);
        Assertion assertion = decryptAssertion(encrypted);
        validateSignature(assertion);
        return assertion;
    }

    /**
     * Validates the encoded assertion.
     *
     * @param encodedAssertion the assertion to validate.
     * @throws Saml2Exception if the assertion is invalid.
     */
    private void validateEncodedAssertion(String encodedAssertion) throws Saml2Exception {
        if (encodedAssertion == null) {
            throw new Saml2Exception("no assertion provided");
        }
    }

    /**
     * Converts the given base64 string to the equivalent raw text string.
     *
     * @param base64 the base64 string to decode.
     * @return the equivalent raw text string.
     * @throws Saml2Exception if the base64 string is invalid.
     */
    private String decodeBase64(String base64) throws Saml2Exception {
        byte[] bytes = Base64.decode(base64);
        if (bytes == null) {
            throw new Saml2Exception("authentication header contained invalid base64 string");
        }
        return new String(bytes);
    }
    
    /**
     * Queso apestoso: afterPropertiesSet was not being called from within Mule. I didn't have time to figure out why,
     * so I created this method to lazily initialize the class.
     * 
     * @throws Saml2Exception if the initialization fails.
     */
    private void initialize() throws Saml2Exception {
        if (!initialized) {
            try {
                afterPropertiesSet();
            }
            catch (Exception e) {
                throw new Saml2Exception("initialization failed", e);
            }
        }
    }

    /**
     * Decrypts the assertion.
     * 
     * @param encrypted the serialized and encrypted assertion.
     * @return the decrypted assertion.
     * @throws Saml2Exception if the assertion can't be decrypted.
     */
    private Assertion decryptAssertion(String encrypted) throws Saml2Exception {
        try {
            return assertionDecrypter.decryptAssertion(encrypted);
        }
        catch (UnmarshallingException e) {
            String msg = "unable to decrypt the assertion";
            logger.debug(msg);
            throw new Saml2Exception(msg);
        }
    }

    /**
     * Validates the signature on the given SAML assertion.
     * 
     * @param assertion the assertion to validate.
     * @throws Saml2Exception if the assertion signature can't be validated.
     */
    private void validateSignature(Assertion assertion) throws Saml2Exception {
        if (!signatureValidator.isValid(assertion)) {
            String msg = "unable to validate the assertion signature";
            logger.debug(msg);
            throw new Saml2Exception(msg);
        }
    }
}
