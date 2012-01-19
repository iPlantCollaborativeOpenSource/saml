package org.iplantc.saml;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds a SAML assertion and provides several methods that can be used to modify and format the assertion. The
 * assertion may be modified until it is marshalled (that is, until it has been converted to its XML representation).
 * After the assertion has been marshalled any attempt to modify it will result in a Saml2Exception.
 * 
 * @author Dennis Roberts
 * 
 *         TODO modify class so that it only throws descendants of Saml2Exception.
 */
public class AssertionBuilder {

    /**
     * A factory to create various object builders.
     */
    private XMLObjectBuilderFactory builderFactory;

    /**
     * The assertion that we're building.
     */
    private Assertion assertion;

    /**
     * The logger.
     */
    private final Logger logger = LoggerFactory.getLogger(AssertionBuilder.class);

    /**
     * Creates a default assertion builder. I know we're limited to SAML2 assertions by the lack of dependency
     * injection, but there's not much we can do; the Assertion interface is different for SAML1 and SAML2 and there's
     * no single common super interface.
     */
    public AssertionBuilder() {
        Bootstrap.bootstrap();
        builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<Assertion> builder = getAssertionBuilder();
        assertion = builder.buildObject();
        logger.debug("building a new assertion {}", assertion);
    }

    /**
     * Obtains an assertion builder from the builder factory. The purpose of this method is to limit the scope of the
     * SuppressWarnings annotation to just the statement that needs it.
     * 
     * @return the assertion builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<Assertion> getAssertionBuilder() {
        return (SAMLObjectBuilder<Assertion>) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Obtains an authentication statement builder from the builder factory. The purpose of this method is to limit the
     * scope of the SuppressWarnings annotation to just the statement that needs it.
     * 
     * @return the authentication statement builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<AuthnStatement> getAuthnStatementBuilder() {
        return (SAMLObjectBuilder<AuthnStatement>) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Obtains an authentication context builder from the builder factory. The purpose of this method is to limit the
     * scope of the SuppressWarnings annotation to just the statement that needs it.
     * 
     * @return the authentication context builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<AuthnContext> getAuthnContextBuilder() {
        return (SAMLObjectBuilder<AuthnContext>) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Obtains an authentication context class reference builder from the builder factory. The purpose of this method is
     * to limit the scope of the SuppressWarnings annotation to just the statement that needs it.
     * 
     * @return the authentication context class reference builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<AuthnContextClassRef> getAuthnContextClassRefBuilder() {
        return (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Creates a signature element. The purpose of this method is to limit the scope of the SuppressWarnings annotation
     * to just the statements that need it.
     * 
     * @return the signature element.
     */
    @SuppressWarnings("unchecked")
    private Signature getSignature() {
        XMLObjectBuilder builder = builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        return (Signature) builder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
    }

    /**
     * In some cases, it may be necessary to do things with the assertion that aren't directly supported by this class.
     * This method allows the user to access the assertion directly.
     * 
     * @return the assertion that is being built.
     */
    public Assertion getAssertion() {
        logger.debug("returning assertion {} to the caller", assertion);
        return assertion;
    }

    /**
     * Verifies that the assertion hasn't been marshalled already. An assertion is marshalled any time it is signed or
     * encrypted.
     * 
     * @throws Saml2Exception if the assertion has already been marshalled.
     */
    private void verifyNotMarshalled() throws Saml2Exception {
        if (assertion.getDOM() != null) {
            String msg = "illegal attempt to modify an assertion that has been signed or encrypted";
            logger.error(msg);
            throw new Saml2Exception(msg);
        }
    }

    /**
     * Sets the subject of the assertion.
     * 
     * @param name the name of the subject.
     * @throws Saml2Exception if the assertion has already been marshalled.
     */
    public void setSubject(String name) throws Saml2Exception {
        verifyNotMarshalled();
        assertion.setSubject(new SubjectBuilder(name).getSubject());
        logger.debug("set the assertion subject name of {} to {}", assertion, name);
    }

    /**
     * Adds an authentication method to the assertion.
     * 
     * @param authnMethod the method of authentication.
     * @param authnInstant the date and time of authentication.
     * @throws Saml2Exception if the assertion has already been marshalled.
     */
    public void addAuthnMethod(String authnMethod, DateTime authnInstant) throws Saml2Exception {
        verifyNotMarshalled();
        AuthnStatement authnStatement = getAuthnStatementBuilder().buildObject();
        authnStatement.setAuthnInstant(authnInstant);
        AuthnContext authnContext = getAuthnContextBuilder().buildObject();
        AuthnContextClassRef authnContextClassRef = getAuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setAuthnContextClassRef(authnMethod);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);
        logger.debug("added a new authentidation method to assertion {}: method = {}, instant = {}",
                new Object[] { assertion, authnMethod, authnInstant });
    }

    /**
     * Adds an authentication method to the assertion.
     * 
     * @param authnMethod the method of authentication.
     * @throws Saml2Exception if the assertion has already been marshalled.
     */
    public void addAuthnMethod(String authnMethod) throws Saml2Exception {
        addAuthnMethod(authnMethod, new DateTime());
    }

    /**
     * Adds an authentication method to the assertion.
     * 
     * @param authnMethod the method of authentication.
     * @param authnInstant the date and time of authentication.
     * @throws Saml2Exception if the assertion has already been marshalled.
     */
    public void addAuthnMethod(String authnMethod, String authnInstant) throws Saml2Exception {
        DateTimeFormatter formatter = ISODateTimeFormat.dateTime();
        addAuthnMethod(authnMethod, formatter.parseDateTime(authnInstant));
    }

    /**
     * Adds an attribute statement to the assertion and returns a Saml2AttributeStatementBuilder that can be used to add
     * attributes to the attribute statement.
     * 
     * @return a builder that can be used to add attributes to the attribute statement.
     * @throws Saml2Exception if the assertion has already been marshalled.
     */
    public AttributeStatementBuilder addAttributeStatement() throws Saml2Exception {
        verifyNotMarshalled();
        AttributeStatementBuilder builder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement = builder.getAttributeStatement();
        assertion.getAttributeStatements().add(attributeStatement);
        logger.debug("added a new attribute statement {} to assertion {}", attributeStatement, assertion);
        return builder;
    }

    /**
     * Converts the assertion to an XML document.
     * 
     * @return the formatted assertion.
     * @throws MarshallingException if the assertion can't be formatted.
     */
    public String formatAssertion() throws MarshallingException {
        logger.debug("formatting assertion {}", assertion);
        return new Formatter().format(assertion);
    }

    /**
     * Signs and formats the assertion.
     * 
     * @param keyPair the key pair used to sign the assertion.
     * @param algorithm the algorithm used to generate the key pair.
     * @return The signed and formatted assertion.
     * @throws MarshallingException if the assertion can't be signed or formatted.
     */
    public void signAssertion(X509Certificate cert, PrivateKey privateKey, String algorithm)
            throws MarshallingException
    {
        BasicX509Credential credential = SecurityHelper.getSimpleCredential(cert, privateKey);
        Signature signature = getSignature();
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(algorithm);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setKeyInfo(getKeyInfo(credential));
        assertion.setSignature(signature);
        Formatter formatter = new Formatter();
        formatter.marshall(assertion);
        signAssertion(signature);
    }

    /**
     * Signs the assertion.
     * 
     * @param signature the signature used to sign the assertion.
     * @throws MarshallingException if the assertion can't be signed.
     */
    private void signAssertion(Signature signature) throws MarshallingException {
        try {
            Signer.signObject(signature);
        }
        catch (SignatureException e) {
            String msg = "unable to sign assertion " + assertion;
            logger.error(msg, e);
            throw new MarshallingException(msg, e);
        }
    }

    /**
     * Builds the KeyInfo element for the given credential.
     * @param credential
     * @return
     * @throws MarshallingException
     */
    private KeyInfo getKeyInfo(BasicX509Credential credential) throws MarshallingException {
        try {
            X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            keyInfoGeneratorFactory.setEmitEntityCertificate(true);
            return keyInfoGeneratorFactory.newInstance().generate(credential);
        }
        catch (SecurityException e) {
            String msg = "unable to generate the signing key information";
            logger.error(msg, e);
            throw new MarshallingException(msg, e);
        }
    }
}
