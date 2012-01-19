package org.iplantc.saml;

import static org.iplantc.saml.util.XMLFileAssert.assertXMLEqualToFile;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.iplantc.saml.util.KeyLoader;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that we can successfully build SAML2 attribute statements.
 * 
 * @author Dennis Roberts
 */
public class AttributeStatementBuilderTest {

    private static final String EDUPERSON_URL = "http://www.educause.edu/eduperson/";

    /**
     * The attribute statement builder to use for all tests.
     */
    private AttributeStatementBuilder builder;

    /**
     * A logger to use for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(AttributeStatementBuilderTest.class);

    /**
     * Initializes each test.
     */
    @Before
    public void initialize() {
        builder = new AttributeStatementBuilder();
    }

    /**
     * Verifies that we can build an empty attribute statement.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldBuildEmptyAttributeStatement() throws Exception {
        logger.debug("Verifying that we can build an empty attribute statement...");
        assertXMLEqualToFile("EmptySamlAttributeStatement.xml", builder.formatAttributeStatement());
    }

    /**
     * Verifies that we can add a string attribute to an attribute statement.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAddStringAttribute() throws Exception {
        logger.debug("Verifying that we can add a string attribute to the attribute statement...");
        builder.addStringAttribute("displayName", EDUPERSON_URL, "Nobody Inparticular");
        assertXMLEqualToFile("SamlAttributeStatementWithStringAttribute.xml", builder.formatAttributeStatement());
    }

    /**
     * Verifies that we can add more than one attribute to an attribute statement.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAddMultipleStringAttributes() throws Exception {
        logger.debug("Verifying that we can add multiple string attributes...");
        builder.addStringAttribute("eduPersonPrincipalName", EDUPERSON_URL, "nobody@iplantcollaborative.org");
        builder.addStringAttribute("displayName", EDUPERSON_URL, "Nobody Inparticular");
        assertXMLEqualToFile("SamlAttributeStatementWithMultipleAttributes.xml", builder.formatAttributeStatement());
    }
    
    /**
     * Verifies that we can't add an attribute to an attribute statement that has been signed.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=Saml2Exception.class)
    public void shouldNotBeAbleToAddAttributeToSignedAttributeStatement() throws Exception {
        logger.debug("Verifying that we can't add an attribute to a signed attribute statement...");
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        builder = assertionBuilder.addAttributeStatement();
        KeyLoader keyLoader = new KeyLoader();
        X509Certificate certificate = keyLoader.loadCertificate("signing");
        PrivateKey privateKey = keyLoader.loadPrivateKey("signing");
        assertionBuilder.signAssertion(certificate, privateKey, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        builder.addStringAttribute("displayName", EDUPERSON_URL, "Nobody Inparticular");
    }
}
