package org.iplantc.saml.util;

/**
 * Represents an HTTP Servlet request attribute that should be included as a user attribute in a SAML assertion.
 * 
 * @author lenards
 */
public class RequestAttribute {
    private static final String PREFIX = "HTTP_";

    /**
     * The name of the attribute as it appears in the servlet request.
     */
    private String attributeName;

    /**
     * The name of the attribute as it will appear in the SAML assertion.
     */
    private String camelCaseName;

    /**
     * The default constructor.
     * 
     * @param attribute the name of the attribute as it appears in the servlet request.
     */
    public RequestAttribute(String attribute) {
        attributeName = attribute;
        camelCaseName = properCase(attribute);
    }

    /**
     * Converts the attribute name as it appears in the servlet request to the name as it will appear in the assertion. 
     * 
     * @param attribute the attribute name as it appears in the servlet request.
     * @return the attribute name as it appears in the assertion.
     */
    private String properCase(String attribute) {
        String suffix = attribute.substring(PREFIX.length());
        suffix = suffix.toLowerCase();
        return suffix;
    }

    /**
     * Gets the attribute name as it appears in the servlet request.
     * 
     * @return the attribute name.
     */
    public String getAttributeName() {
        return attributeName;
    }

    /**
     * Gets the attribute name as it appears in the assertion.
     * 
     * @return the attribute name.
     */
    public String getDisplayName() {
        return camelCaseName;
    }
}
