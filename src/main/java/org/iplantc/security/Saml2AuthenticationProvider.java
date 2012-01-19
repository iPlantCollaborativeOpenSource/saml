package org.iplantc.security;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.providers.AuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides authentication for reqeusts containing SAML assertions.
 * 
 * @author Dennis Roberts
 */
public class Saml2AuthenticationProvider implements AuthenticationProvider {

    /**
     * A logger for error and informational messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2AuthenticationProvider.class);

    /**
     * Determines whether or not an exception is thrown when the token is rejected. If this option is enabled then all
     * failed authentications will result in an authentication exception. Otherwise, all failed authentications will
     * result in a null pointer being returned. An exception indicates that the authentication failed, so this option
     * should be enabled in cases where we expect all requests to contain SAML assertions.
     */
    private boolean throwExceptionWhenTokenRejected = false;

    /**
     * Setter for the throwExceptionWhenTokenRejected flag.
     * 
     * @param newValue the new value of the flag.
     */
    public void setThrowExceptionWhenTokenRejected(boolean newValue) {
        throwExceptionWhenTokenRejected = newValue;
    }

    /**
     * Attempts to authenticate the user.
     * 
     * @param authentication the authentication request.
     * @return an completed authentication request or null if the authentication couldn't be completed.
     * @thorws AuthenticationException if the authentication fails.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }
        return validateAuthentication(authentication);
    }

    /**
     * Determines whether or not the authentication is valid.
     * 
     * @param authentication the authentication to validate.
     * @return the completed authentication request.
     * @throws AuthenticationException if the authentication fails.
     */
    private Authentication validateAuthentication(Authentication authentication) throws AuthenticationException {
        try {
            validateUsername(authentication);
            authentication.setAuthenticated(true);
            return authentication;
        }
        catch (AuthenticationException e) {
            logger.debug("authentication failed");
            if (throwExceptionWhenTokenRejected) {
                throw e;
            }
            return null;
        }
    }

    /**
     * Validates the username in the authentication request.
     * 
     * @param authentication the authentication request to validate.
     * @throws AuthenticationException if the authentication fails.
     */
    private void validateUsername(Authentication authentication) throws AuthenticationException {
        if (authentication.getName() == null) {
            String msg = "no subject name found in SAML assertion";
            logger.debug(msg);
            throw new BadCredentialsException(msg);
        }
    }

    /**
     * Determines whether or not this authentication provider supports attempts to authenticate using the given class.
     * 
     * @param authentication the class containing the authentication request.
     * @return true if this authentication provider supports the given type of authentication request.
     */
    @SuppressWarnings("rawtypes")
    public boolean supports(Class authentication) {
        return Saml2AuthenticationToken.class.isAssignableFrom(authentication);
    }
}
