package org.iplantc.saml;

import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;
import static org.iplantc.saml.util.XMLFileAssert.assertXMLEqualToFile;

import java.io.StringReader;

import org.iplantc.saml.util.FileSlurper;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Verifies that we can successfully convert SAML objects to XML documents.
 * 
 * @author Dennis Roberts
 */
public class FormatterTest {

    /**
     * The formatter used for all tests.
     */
    private Formatter formatter = null;

    /**
     * The logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(FormatterTest.class);

    /**
     * Initializes each test.
     */
    @Before
    public void initialize() {
        formatter = new Formatter();
    }

    /**
     * Verifies that we can marhsall an empty assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldMarshallEmptyAssertion() throws Exception {
        logger.debug("Verifying tht we can marshall an empty SAML2 assertion...");
        Assertion assertion = new AssertionBuilder().buildObject();
        assertXMLEqualToFile("EmptySamlAssertion.xml", formatter.marshall(assertion));
    }

    /**
     * Verifies that we can marshall an empty authentication context.
     *
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldMarshallEmptyAuthenticationContext() throws Exception {
        logger.debug("Verifying that we can marshall an empty SAML2 authentication context...");
        AuthnContext context = new AuthnContextBuilder().buildObject();
        assertXMLEqualToFile("EmptySamlAuthnContext.xml", formatter.marshall(context));
    }

    /**
     * Verifies that we can format an empty assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldFormatEmptyAssertion() throws Exception {
        logger.debug("Verifying that we can format an empty SAML2 assertion...");
        Assertion assertion = new AssertionBuilder().buildObject();
        assertXMLEqualToFile("EmptySamlAssertion.xml", formatter.format(assertion));
    }

    /**
     * Verifies that we can format an empty authentication context.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldFormatEmptyAuthenticationContext() throws Exception {
        logger.debug("Verifying that we can format an empty SAML authenticaiton context...");
        AuthnContext context = new AuthnContextBuilder().buildObject();
        assertXMLEqualToFile("EmptySamlAuthnContext.xml", formatter.format(context));
    }

    /**
     * Verifies that we can format an assertion element directly.
     *
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldFormatEmptyAssertionElement() throws Exception {
        logger.debug("Verifying that we can format an assertion element directly...");
        Assertion assertion = new AssertionBuilder().buildObject();
        Element assertionElement = formatter.marshall(assertion);
        assertXMLEqualToFile("EmptySamlAssertion.xml", formatter.format(assertionElement));
    }

    /**
     * Verifies that we can format an authentication context element directly.
     *
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldFormatEmptyAuthenticationContextElement() throws Exception {
        logger.debug("Verifying that we can format an authentication context element directly...");
        AuthnContext context = new AuthnContextBuilder().buildObject();
        Element contextElement = formatter.marshall(context);
        assertXMLEqualToFile("EmptySamlAuthnContext.xml", formatter.format(contextElement));
    }

    /**
     * Verifies that we can unmarshall an assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldUnmarshallAssertion() throws Exception {
        logger.debug("Verifying tht we can unmarshall a string containing an assertion...");
        String expected = new FileSlurper().slurp("ComplexSamlAssertion.xml");
        String actual = formatter.format(formatter.unmarshall(expected));
        assertXMLEqual(expected, actual);
    }

    /**
     * Verifies that we can unmarshall an XML document element directly.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldUnmarshallElement() throws Exception {
        logger.debug("Verifying that we can unmarshall an element containing an assertion...");
        String expected = new FileSlurper().slurp("ComplexSamlAssertion.xml");
        BasicParserPool parser = new BasicParserPool();
        Document document = parser.parse(new StringReader(expected));
        String actual = formatter.format(formatter.unmarshall(document.getDocumentElement()));
        assertXMLEqual(expected, actual);
    }
    
    /**
     * Verifies that we get an UnmarshallingException for bogus XML.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=UnmarshallingException.class)
    public void shouldNotUnmarshallBogusXml() throws Exception {
        logger.debug("Verifying that we get an UnmarshallingException for bogus XML...");
        String xml = "I'm a baaaaaaaaad piece of XML!";
        formatter.unmarshall(xml);
    }
}
