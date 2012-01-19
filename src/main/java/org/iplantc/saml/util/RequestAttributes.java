package org.iplantc.saml.util;

import java.util.ArrayList;
import java.util.List;

/**
 * Creates a list of attributes that are known to be provided by Shibboleth.
 * 
 * @author lenards
 */
public class RequestAttributes {

    /**
     * The list of known attribute names as they appear in the servlet request.
     */
    private static final String[] _knownAttributes = {
    	"HTTP_SHIB_SESSION_ID",            	"HTTP_SHIB_IDENTITY_PROVIDER",
    	"HTTP_SHIB_AUTHNCONTEXT_CLASS",    	"HTTP_SHIB_AUTHNCONTEXT_DECL",
    	"HTTP_SHIB_ASSERTION_COUNT",       	"HTTP_AFFILIATION",         
    	"HTTP_UNSCOPED_AFFILIATION",		"HTTP_ENTITLEMENT",
    	"HTTP_ASSURANCE",					"HTTP_TARGETED_ID",                
    	"HTTP_PERSISTENT_ID",				"HTTP_SHIB_APPLICATION_ID",
    	"HTTP_REMOTE_USER",
    };

    /**
     * The name of the attribute containing the authentication method.  This attribute has a dedicated place in the
     * SAML assertion.
     */
    public static final String AUTHENTICATION_METHOD = "HTTP_SHIB_AUTHENTICATION_METHOD";

    
    /**
     * The name of the attribute containing the date and time that the user was authenticated.  This attribute has a
     * dedicated place in the SAML assertion.
     */
    public static final String AUTHENTICATION_INSTANT = "HTTP_SHIB_AUTHENTICATION_INSTANT";

    /**
     * The name of the attribute containing the eduPersonPrincipalName.  This attribute is being used as the subject
     * name in the SAML assertion
     */
    public static final String EDUPERSON = "HTTP_EPPN";

    /**
     * The list of known attributes.
     */
    private static final List<RequestAttribute> knownAttributes = new ArrayList<RequestAttribute>();

    /**
     * Initializes the list of known attributes.
     */
    static {
    	for (int i = 0; i < _knownAttributes.length; i++) {
    		knownAttributes.add(new RequestAttribute(_knownAttributes[i]));
    	}
    }

    /**
     * Gets the list of known attributes.
     * 
     * @return the list of known attributes.
     */
    public static List<RequestAttribute> getKnownAttributes() {
    	return knownAttributes;
    }
}
