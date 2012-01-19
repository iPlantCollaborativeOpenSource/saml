package org.iplantc.security;

import java.util.Arrays;

import org.iplantc.saml.AssertionBuilder;
import org.iplantc.saml.AttributeStatementBuilder;
import org.iplantc.saml.Saml2Exception;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that we can extract user details from SAML assertions.
 *
 * @author Dennis Roberts
 */
public class Saml2UserDetailsFromAssertionTest {

    /**
     * The user details to use for most of the tests.
     */
    private Saml2UserDetails details;
    
    /**
     * The logger to use for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2UserDetailsFromAssertionTest.class);

    /**
     * Initializes each test.
     *
     * @throws Saml2Exception if the assertion can't be built.
     */
    @Before
    public void initialize() throws Saml2Exception, MarshallingException {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        assertionBuilder.setSubject("nobody@iplantcollaborative.org");
        assertionBuilder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        AttributeStatementBuilder attributeStatementBuilder = assertionBuilder.addAttributeStatement();
        attributeStatementBuilder.addStringAttribute("foo", "http://www.example.org", "blarg");
        attributeStatementBuilder.addStringAttribute("bar", "http://www.example.org", "glarb");
        attributeStatementBuilder.addStringAttribute("baz", "http://www.example.org", "blurfl");
        details = new Saml2UserDetails(assertionBuilder.getAssertion());
    }

    /**
     * Verifies that the username is successfully extracted from the assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldGetUserNameFromAssertion() throws Exception {
        logger.debug("Verifying that the username is successfully extracted from the assertion...");
        assertEquals("nobody@iplantcollaborative.org", details.getUsername());
    }
    
    /**
     * Verifies that the user's attributes are successfully extracted from the assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldGetAttributesFromAssertion() throws Exception {
        logger.debug("Verifying that the user attributes are successfully extracted from the assertion...");
        assertEquals(Arrays.asList("blarg"), details.getAttribute("foo"));
        assertEquals(Arrays.asList("glarb"), details.getAttribute("bar"));
        assertEquals(Arrays.asList("blurfl"), details.getAttribute("baz"));
    }

    /**
     * Verifies that we can handle a SAML assertion without a subject.
     *
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAcceptAssertionWithoutSubject() throws Exception {
        logger.debug("Verifying that we can handle an assertion without a subject.");
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        AttributeStatementBuilder attributeStatementBuilder = assertionBuilder.addAttributeStatement();
        attributeStatementBuilder.addStringAttribute("foo", "http://www.example.org", "blarg");
        details = new Saml2UserDetails(assertionBuilder.getAssertion());
        assertNull(details.getUsername());
    }
}
