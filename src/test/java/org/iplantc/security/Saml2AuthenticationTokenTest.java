package org.iplantc.security;

import static org.junit.Assert.*;

import org.iplantc.saml.AssertionBuilder;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

public class Saml2AuthenticationTokenTest {

    /**
     * A logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2AuthenticationTokenTest.class);
    
    /**
     * The authentication token used for testing.
     */
    private Saml2AuthenticationToken authenticationToken;
    
    /**
     * The assertion used to generate the authentication token.
     */
    private Assertion assertion;
    
    /**
     * Initializes each test.
     * 
     * @throws Exception if an error occurs.
     */
    @Before
    public void initialize() throws Exception {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        assertionBuilder.setSubject("nobody@iplantcollaborative.org");
        assertionBuilder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        assertion = assertionBuilder.getAssertion();
        authenticationToken = new Saml2AuthenticationToken(assertion, "some credentials");
    }

    /**
     * Verifies that we can retrieve the user's credentials.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldGetCredentials() throws Exception {
        logger.debug("Verifying that we can retrieve the user's credentials...");
        assertEquals("some credentials", authenticationToken.getCredentials());
    }

    /**
     * Verifies that we can retrieve the SAML assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldGetAssertion() throws Exception {
        logger.debug("Verifying that we can retrieve the SAML assertion...");
        assertSame(assertion, authenticationToken.getAssertion());
    }

    /**
     * Verifies that username is successfully extracted from the SAML assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldExtractUsername() throws Exception {
        logger.debug("Verifying that the username is successfully extracted from the assertion...");
        assertEquals("nobody@iplantcollaborative.org", authenticationToken.getName());
    }

    /**
     * Verifies that the user details are generated directly from the assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldGenerateUserDetails() throws Exception {
        logger.debug("Verifying that the user details are generated directly from the assertion...");
        Saml2UserDetails expected = new Saml2UserDetails(assertion);
        assertEquals(expected, authenticationToken.getDetails());
    }
    
    /**
     * Verifies that the user details are returned as the principal information.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldReturnUserDetailsAsPrincipal() {
        logger.debug("Verifying that getPrincipal() returns the user details...");
        assertSame(authenticationToken.getDetails(), authenticationToken.getPrincipal());
    }
    
    /**
     * Verifies that the authenticated flag is initially false.
     */
    @Test
    public void authenticatedFlagShouldInitiallyBeFalse() {
        logger.debug("Verifying that the authenticated flag is initially false...");
        assertFalse(authenticationToken.isAuthenticated());
    }

    /**
     * Verifies that the authenticated flag can be altered.
     */
    @Test
    public void shouldSetAuthenticatedFlag() {
        logger.debug("Verifying that we can alter the value of the authenticated flag...");
        authenticationToken.setAuthenticated(true);
        assertTrue(authenticationToken.isAuthenticated());
    }

    /**
     * Verifies that the granted authorities are what we expect them to be.
     */
    @Test
    public void grantedAuthoritiesShouldContainOnlyRoleUser() {
        logger.debug("Verifying that the granted authorities array only contains ROLE_USER...");
        GrantedAuthority[] expected = new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_USER") };
        assertArrayEquals(expected, authenticationToken.getAuthorities());
    }
}
