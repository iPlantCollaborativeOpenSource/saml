package org.iplantc.security;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.iplantc.saml.AssertionDecrypter;
import org.iplantc.saml.SignatureValidator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.ui.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;

public class Saml2PreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

    /**
     * A logger for error and informational messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2SecurityFilter.class);

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
    }

    /**
     * Loads the keystore.
     * 
     * @throws IOException if an I/O error occurs.
     * @throws GeneralSecurityException if the keystore can't be loaded.
     */
    private void loadKeyStore() throws IOException, GeneralSecurityException {
        FileInputStream in = null;
        try {
            keystore = KeyStore.getInstance(keyStoreType);
            in = new FileInputStream(keyStorePath);
            keystore.load(in, keyStorePassword.toCharArray());
        }
        finally {
            if (in != null) {
                in.close();
            }
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
        PublicKey publicKey = keystore.getCertificate(alias).getPublicKey();
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
     * Setter for the keyStorePassword property.
     * 
     * @param keyStorePassword the password used to access the keystore.
     */
    public void setKeyStorePassword(String keyStorePassword) {
        Assert.notNull(keyStorePassword, "a keystore password is required");
        this.keyStorePassword = keyStorePassword;
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
     * Setter for the keyEncryptingKeyPairAlias property.
     * 
     * @param alias the alias used to refer to the key encrypting key pair in the keystore.
     */
    public void setKeyEncryptingKeyPairAlias(String alias) {
        Assert.notNull(alias, "an alias is required");
        keyEncryptingKeyPairAlias = alias;
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
     * {@inheritDoc}
     */
    @Override
    public int getOrder() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String encrypted = getEncryptedAssertion(request);
        Assertion assertion = decryptAssertion(encrypted);
        validateSignature(assertion);
        Saml2AuthenticationToken authnRequest = getAuthnRequest(assertion);
        return authnRequest;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return getEncryptedAssertion(request);
    }

    /**
     * Obtains the user details object.
     * 
     * @param assertion the assertion to get the user details from.
     * @return the user details.
     */
    private Saml2AuthenticationToken getAuthnRequest(Assertion assertion) {
        try {
            return new Saml2AuthenticationToken(assertion);
        }
        catch (MarshallingException e) {
            String msg = "unable to extract the user details from the assertion";
            logger.debug(msg);
            throw new BadCredentialsException(msg);
        }
    }

    /**
     * Decrypts the assertion.
     * 
     * @param encrypted the serialized and encrypted assertion.
     * @return the decrypted assertion.
     */
    private Assertion decryptAssertion(String encrypted) {
        try {
            return assertionDecrypter.decryptAssertion(encrypted);
        }
        catch (UnmarshallingException e) {
            String msg = "unable to decrypt the assertion";
            logger.debug(msg);
            throw new BadCredentialsException(msg);
        }
    }

    /**
     * Validates the signature on the given SAML assertion.
     * 
     * @param assertion the assertion to validate.
     */
    private void validateSignature(Assertion assertion) {
        if (!signatureValidator.isValid(assertion)) {
            String msg = "unable to validate the assertion signature";
            logger.debug(msg);
            throw new BadCredentialsException(msg);
        }
    }

    /**
     * Extracts the encrypted assertion from the HTTP header.
     * 
     * @param request the HTTP request.
     * @return the encrypted assertion as a string.
     */
    private String getEncryptedAssertion(HttpServletRequest request) {
        String base64 = request.getHeader(SecurityConstants.ASSERTION_HEADER);
        if (base64 == null) {
            String msg = "no SAML assertion found";
            throw new BadCredentialsException(msg);
        }
        return new String(Base64.decode(base64));
    }
}
