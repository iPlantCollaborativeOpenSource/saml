package org.iplantc.saml.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

/**
 * Provides a simple mechanism to load keys from the test keystore.
 * 
 * @author Dennis Roberts
 */
public class KeyLoader {

    /**
     * The elements of the path to the keystore.
     */
    private static final String[] KEYSTORE_PATH_ELEMENTS = { "src", "test", "resources", "test.jceks" };

    /**
     * The path to the keystore.
     */
    private static final String KEYSTORE_PATH = PathBuilder.buildPath(KEYSTORE_PATH_ELEMENTS);

    /**
     * The keystore password.
     */
    private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();
    
    /**
     * The keystore.
     */
    private KeyStore keystore;

    /**
     * Loads the keystore.
     * 
     * @throws GeneralSecurityException if the keystore can't be loaded.
     * @throws IOException if an I/O error occurs.
     */
    public KeyLoader() throws GeneralSecurityException, IOException {
        keystore = loadKeyStore();
    }

    /**
     * Loads the key pair with the given alias from the test keystore.
     * 
     * @param alias the key pair alias.
     * @return the key pair.
     * @throws GeneralSecurityException if the key pair can't be loaded.
     */
    public KeyPair loadKeyPair(String alias) throws GeneralSecurityException {
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, KEYSTORE_PASSWORD);
        PublicKey publicKey = keystore.getCertificate(alias).getPublicKey();
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Loads the certificate with the given alias from the test keystore.
     * 
     * @param alias the certificate alias.
     * @return the certificate.
     * @throws GeneralSecurityException if the certificate can't be retrieved.
     */
    public X509Certificate loadCertificate(String alias) throws GeneralSecurityException {
        return (X509Certificate) keystore.getCertificate(alias);
    }

    /**
     * Loads the private key with the given alias from the test keystore.
     * 
     * @param alias the private key alias.
     * @return the private key.
     * @throws GeneralSecurityException if the private key can't be loaded.
     */
    public PrivateKey loadPrivateKey(String alias) throws GeneralSecurityException {
        return (PrivateKey) keystore.getKey(alias, KEYSTORE_PASSWORD);
    }

    /**
     * Loads the secret key with the given alias from the test keystore.
     *
     * @param alias the key alias.
     * @return the key.
     * @throws GeneralSecurityException if the key can't be loaded.
     */
    public SecretKey loadSecretKey(String alias) throws GeneralSecurityException {
        return (SecretKey) keystore.getKey(alias, KEYSTORE_PASSWORD);
    }

    /**
     * Loads the test keystore.
     * 
     * @return the keystore.
     * @throws GeneralSecurityException if the keystore can't be loaded.
     * @throws IOException if an I/O error occurs.
     */
    private KeyStore loadKeyStore() throws GeneralSecurityException, IOException {
        FileInputStream in = null;
        try {
            KeyStore keystore = KeyStore.getInstance("JCEKS");
            in = new FileInputStream(KEYSTORE_PATH);
            keystore.load(in, KEYSTORE_PASSWORD);
            return keystore;
        }
        finally {
            if (in != null) {
                in.close();
            }
        }
    }
}
