package org.iplantc.security;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.MarshallingException;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

/**
 * Represents an authentication request for which we have a SAML assertion.
 * 
 * @author Dennis Roberts
 */
public class Saml2AuthenticationToken implements Authentication {

    /**
     * The SAML assertion that was used for authentication.
     */
    private Assertion assertion;

    /**
     * The credentials used to authenticate the user; this is typically a serialized version of the assertion.
     */
    private Object credentials;

    /**
     * The principal name from the SAML assertion.
     */
    private Saml2UserDetails principal;

    /**
     * True if the user is authenticated.
     */
    private boolean authenticated;

    /**
     * The version ID for serialization.
     */
    private static final long serialVersionUID = 3360602598008155858L;

    /**
     * Creates a new authentication token.
     * 
     * @param assertion the SAML assertion.
     * @param credentials the credentials used to authenticate the user.
     * @throws MarshallingException if any of the attributes in the assertion can't be marshalled.
     */
    public Saml2AuthenticationToken(Assertion assertion, Object credentials) throws MarshallingException {
        this.assertion = assertion;
        this.credentials = credentials;
        principal = new Saml2UserDetails(assertion);
        authenticated = false;
    }

    /**
     * Creates a new authentication token without credentials.
     * 
     * @param assertion the SAML assertion.
     * @throws MarshallingException if any of the attributes in the assertion can't be marshalled.
     */
    public Saml2AuthenticationToken(Assertion assertion) throws MarshallingException {
        this(assertion, null);
    }
    
    /**
     * Gets the list of granted authorities. For the time being, all users are treated equally.
     * 
     * @return an array of granted authorities.
     */
    public GrantedAuthority[] getAuthorities() {
        return new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_USER") };
    }

    /**
     * Gets the credentials used to authenticate the user.
     * 
     * @return the credentials.
     */
    public Object getCredentials() {
        return credentials;
    }

    /**
     * Gets the user details.
     * 
     * @return the user details.
     */
    public Object getDetails() {
        return principal;
    }

    /**
     * Gets information about the principal.
     * 
     * @return the principal details.
     */
    public Object getPrincipal() {
        return principal;
    }

    /**
     * Returns a flag indicating whether or not the user is authenticated.
     * 
     * @return true if the user is authenticated; false, otherwise.
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * Sets the flag indicating whether or not the user is authenticated.
     * 
     * @param authenticated the new value of the flag.
     */
    public void setAuthenticated(boolean authenticated) throws IllegalArgumentException {
        this.authenticated = authenticated;
    }

    /**
     * Gets the username.
     * 
     * @return the username.
     */
    public String getName() {
        return principal.getUsername();
    }
    
    /**
     * Gets the unmarshalled SAML assertion.
     * 
     * @return the assertion.
     */
    public Assertion getAssertion() {
        return assertion;
    }
}
