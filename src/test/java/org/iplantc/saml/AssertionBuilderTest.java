package org.iplantc.saml;

import static junit.framework.Assert.assertNotNull;
import static org.iplantc.saml.util.XMLFileAssert.assertXMLEqualToFile;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.iplantc.saml.util.KeyLoader;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that we can successfully build SAML assertions.
 * 
 * @author Dennis Roberts
 */
public class AssertionBuilderTest {

    /**
     * The attribute format URL.
     */
    private static final String ATTRIBUTE_URL = "http://www.example.org/attributes/";

    /**
     * The assertion builder used in every test.
     */
    private AssertionBuilder assertionBuilder = null;

    /**
     * A logger to use for debugging.
     */
    private final Logger logger = LoggerFactory.getLogger(AssertionBuilderTest.class);

    /**
     * Signs the assertion that is being built.
     *
     * @param keyAlias the alias of the key used to sign the assertion.
     * @throws Exception if an error occurs.
     */
    private void signAssertion(String keyAlias) throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        X509Certificate certificate = keyLoader.loadCertificate(keyAlias);
        PrivateKey privateKey = keyLoader.loadPrivateKey(keyAlias);
        assertionBuilder.signAssertion(certificate, privateKey, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    }
    
    /**
     * Initializes each test.
     */
    @Before
    public void initialize() {
        assertionBuilder = new AssertionBuilder();
    }

    /**
     * Verifies that we can build an empty assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldBuildEmptyAssertion() throws Exception {
        logger.debug("Verifying that we can build an empty assertion...");
        assertXMLEqualToFile("EmptySamlAssertion.xml", assertionBuilder.formatAssertion());
    }

    /**
     * Verifies that we can add a subject to an assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldBeAbleToSetSubject() throws Exception {
        logger.debug("Verifying that we can add a subject to an assertion...");
        assertionBuilder.setSubject("nobody");
        assertXMLEqualToFile("SamlAssertionWithSubject.xml", assertionBuilder.formatAssertion());
    }

    /**
     * Verifies that we can add an authentication method to an assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldBeAbleToAddAuthenticationMethod() throws Exception {
        logger.debug("Verifying that we can add an authentication statement to an assertion...");
        assertionBuilder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        assertXMLEqualToFile("SamlAssertionWithAuthnMethod.xml", assertionBuilder.formatAssertion());
    }

    /**
     * Verifies that we can add an attribute statement to the assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldBeAbleToAddAttributeStatement() throws Exception {
        logger.debug("Verifying that we can add an attribute statement to an assertion...");
        AttributeStatementBuilder attributeStatementBuilder = assertionBuilder.addAttributeStatement();
        assertNotNull(attributeStatementBuilder);
        assertXMLEqualToFile("SamlAssertionWithEmptyAttributeStatement.xml", assertionBuilder.formatAssertion());
    }
    
    /**
     * Verifies that we can create a complex assertion.
     *
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldCreateComplexAssertion() throws Exception {
        logger.debug("Verifying that we can create a complex assertion...");
        assertionBuilder.setSubject("nobody@iplantcollaborative.org");
        assertionBuilder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        AttributeStatementBuilder attributeStatementBuilder = assertionBuilder.addAttributeStatement();
        attributeStatementBuilder.addStringAttribute("someAttribute", ATTRIBUTE_URL, "someValue");
        attributeStatementBuilder.addStringAttribute("someOtherAttribute", ATTRIBUTE_URL, "someOtherValue");
        assertXMLEqualToFile("ComplexSamlAssertion.xml", assertionBuilder.formatAssertion());
    }
    
    /**
     * Verifies that we can create a signed assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldCreateSignedAssertion() throws Exception {
        logger.debug("Verifying that we can create a signed assertion...");
        assertionBuilder.setSubject("nobody@iplantcollaborative.org");
        assertionBuilder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        signAssertion("signing");
        assertXMLEqualToFile("SignedSamlAssertion.xml", assertionBuilder.formatAssertion());
    }

    /**
     * Verifies that we can't set the subject of a signed assertion.
     *
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldNotBeAbleToSetSubjectOfSignedAssertion() throws Exception {
        logger.debug("Verifying that we can't set the subject of a signed assertion...");
        signAssertion("signing");
        assertionBuilder.setSubject("nobody@iplantCollaborative.org");
    }

    /**
     * Verifies that we can't set the add an authentication method to a signed assertion.
     *
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldNotBeAbleToAddAuthnMethodToSignedAssertion() throws Exception {
        logger.debug("Verifying that we can't add an authentication method a signed assertion...");
        signAssertion("signing");
        assertionBuilder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
    }

    /**
     * Verifies that we can't set the add an attribute statement to a signed assertion.
     *
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldNotBeAbleToAddAttributeStatementToSignedAssertion() throws Exception {
        logger.debug("Verifying that we can't add an attribute sttatement to a signed assertion...");
        signAssertion("signing");
        assertionBuilder.addAttributeStatement();
    }
}
