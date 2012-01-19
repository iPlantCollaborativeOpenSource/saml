package org.iplantc.saml;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.opensaml.common.SignableSAMLObject;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.CollectionKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates assertion signatures against a set of trusted credentials. A signature is considered to be valid if it was
 * generated using the private key corresponding to one of the certificates in this object's list of credentials.
 * 
 * @author Dennis Roberts
 */
public class SignatureValidator {

    /**
     * The logger for error and informational messages.
     */
    private final Logger logger = LoggerFactory.getLogger(SignatureValidator.class);

    /**
     * The list of trusted credentials.
     */
    private List<Credential> trustedCredentials;

    /**
     * The default constructor.
     */
    public SignatureValidator() {
        Bootstrap.bootstrap();
        trustedCredentials = new LinkedList<Credential>();
    }

    /**
     * Creates a new credential from the given certificate and adds it to the list of trusted credentials.
     * 
     * @param certificate the trusted certificate to add to the list of credentials.
     */
    public void addCredential(X509Certificate certificate) {
        trustedCredentials.add(SecurityHelper.getSimpleCredential(certificate, null));
    }

    /**
     * Obtains the number of credentials in the trusted credential list.
     * 
     * @return the number of credentials in the list.
     */
    public int getCredentialCount() {
        return trustedCredentials.size();
    }

    /**
     * Validates the signature on the given SAML object.
     * 
     * @param object the SAML object to validate.
     * @return true if the signature is valid.
     */
    public boolean isValid(SignableSAMLObject object) {
        try {
            verifyObjectIsSigned(object);
            validateSignatureProfile(object);
            return validateSignature(object);
        }
        catch (SecurityException e) {
            logger.info("SAML signature validation failed for {}: {}", object, e.getMessage());
            logger.debug("exception", e);
            return false;
        }
    }
    
    /**
     * Verifies that the object is actually signed.
     * 
     * @param object the object whose signature is being validated.
     * @throws SecurityException if the object is not signed.
     */
    public void verifyObjectIsSigned(SignableSAMLObject object) throws SecurityException {
        if (object.getSignature() == null) {
            logger.info("SAML object is not signed: {}", object);
            throw new SecurityException("SAML object is not signed");
        }
    }

    /**
     * Validates the profile that was used to sign the SAML object.
     * 
     * @param object the object whose profile is being validated.
     * @throws SecurityException if the profile is invalid.
     */
    private void validateSignatureProfile(SignableSAMLObject object) throws SecurityException {
        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(object.getSignature());
        }
        catch (ValidationException e) {
            logger.info("SAML signature profile validation failed for {}: {}", object, e.getMessage());
            logger.debug("exception", e);
            throw new SecurityException(e);
        }
    }

    /**
     * Validates the signature.
     * 
     * @param object the SAML object whose signature is being validated.
     * @return true if the signature is valid.
     * @throws SecurityException if the signature can't be validated.
     */
    private boolean validateSignature(SignableSAMLObject object) throws SecurityException {
        KeyInfoCredentialResolver keyInfoResolver = new CollectionKeyInfoCredentialResolver(trustedCredentials);
        CollectionCredentialResolver credentialResolver = new CollectionCredentialResolver(trustedCredentials);
        SignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoResolver);
        CriteriaSet criteriaSet = buildCriteriaSet();
        return trustEngine.validate(object.getSignature(), criteriaSet);
    }

    /**
     * Builds the criteria set used to validate the signature.
     * 
     * @return the new criteria set.
     */
    private CriteriaSet buildCriteriaSet() {
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        return criteriaSet;
    }
}
