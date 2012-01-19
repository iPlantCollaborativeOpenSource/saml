package org.iplantc.saml;

/**
 * Indicates that a general SAML exception has occurred. 
 * 
 * @author Dennis Roberts
 */
public class Saml2Exception extends Exception {

    /**
     * Creates a new Saml2Exception.
     *
     * @param msg a brief description of the error.
     */
    public Saml2Exception(String msg) {
        super(msg);
    }

    /**
     * Creates a new Saml2Exception that was caused by the given exception.
     *
     * @param msg a brief description of the error.
     * @param e the exception that caused the error.
     */
    public Saml2Exception(String msg, Exception e) {
        super(msg, e);
    }

    /**
     * The exception's serial version universal identifier.
     */
    private static final long serialVersionUID = -2259421737728006575L;

}
