package org.iplantc.security;

import static org.junit.Assert.*;

import org.iplantc.saml.AssertionBuilder;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.providers.ldap.LdapAuthenticator;

/**
 * Unit test for org.iplantc.security.Saml2AuthenticationProvider.
 * 
 * @author Dennis Roberts
 */
public class Saml2AuthenticationProviderTest {

    /**
     * A logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2AuthenticationProviderTest.class);

    /**
     * The authentication provider to use for all of the unit tests.
     */
    private Saml2AuthenticationProvider authnProvider;

    /**
     * Initializes each test.
     */
    @Before
    public void initialize() {
        authnProvider = new Saml2AuthenticationProvider();
    }

    /**
     * Verifies that the authentication provider supports instances of Saml2AuthenticationToken.
     */
    @Test
    public void shouldSupportSaml2AuthenticationTokens() {
        logger.debug("Verifying that the authentication provider supports instances of Saml2AuthenticationToken...");
        assertTrue(authnProvider.supports(Saml2AuthenticationToken.class));
    }

    /**
     * Verifies that the authentication provider doesn't support other authentication request types.
     */
    @Test
    public void shouldNotSupportOtherAuthenticationRequests() {
        logger.debug("Verifying that the authentication provider does not support other authentication requests...");
        assertFalse(authnProvider.supports(LdapAuthenticator.class));
    }

    /**
     * Verifies that valid authentication requests are accepted.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAuthenticate() throws Exception {
        logger.debug("Verifying that a valid authentication request is accepted...");
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        assertionBuilder.setSubject("nobody@iplantcollaborative.org");
        Saml2AuthenticationToken authentication = new Saml2AuthenticationToken(assertionBuilder.getAssertion());
        assertNotNull(authnProvider.authenticate(authentication));
        assertTrue(authentication.isAuthenticated());
    }

    /**
     * Verifies that authentication requests without subjects are not accepted.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldNotAuthenticateWithoutSubject() throws Exception {
        logger.debug("Verifying that an authentication request without a subject is rejected...");
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Saml2AuthenticationToken authentication = new Saml2AuthenticationToken(assertionBuilder.getAssertion());
        assertNull(authnProvider.authenticate(authentication));
        assertFalse(authentication.isAuthenticated());
    }

    /**
     * Verifies that the authentication provider throws an exception when authentication fails if we request it to.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected=BadCredentialsException.class)
    public void shouldThrowExceptionOnAuthenticaitonFailureIfAsked() throws Exception {
        logger.debug("Verifying that the authentication provider can throw an exception when authentication fails...");
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Saml2AuthenticationToken authentication = new Saml2AuthenticationToken(assertionBuilder.getAssertion());
        authnProvider.setThrowExceptionWhenTokenRejected(true);
        authnProvider.authenticate(authentication);
    }
}
