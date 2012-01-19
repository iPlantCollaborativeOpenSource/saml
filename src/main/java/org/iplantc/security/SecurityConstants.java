package org.iplantc.security;

/**
 * Constants used throughout this package.
 * 
 * @author Dennis Roberts
 */
public class SecurityConstants {

    /**
     * The HTTP header containing the SAML assertion.
     */
    public static final String ASSERTION_HEADER = "_iplant_auth";

    /**
     * The HTTP header containing the foundational API token.
     */
    public static final String FOUNDATIONAL_API_TOKEN_HEADER = "Authorization";
}
