 package org.iplantc.security;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.iplantc.saml.Formatter;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.util.Assert;
import org.w3c.dom.Element;

/**
 * Provides details about the authenticated user.
 * 
 * @author Dennis Roberts
 */
public class Saml2UserDetails implements UserDetails {

    /**
     * A logger for error and informational messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2UserDetails.class);

    /**
     * The name of the authenticated user.
     */
    private String username;

    /**
     * The user's attributes.
     */
    private Hashtable<String, List<String>> attributes;

    /**
     * Used to unmarshall the user attributes.
     */
    private Formatter marshaller;

    /**
     * The serial version universal identifier.
     */
    private static final long serialVersionUID = -2908285082260308731L;

    /**
     * Creates a new user details record.
     * 
     * @param username the username.
     */
    public Saml2UserDetails(String username) {
        this.username = username;
        attributes = new Hashtable<String, List<String>>();
        marshaller = new Formatter();
    }

    /**
     * Populates the new user details record using the given SAML assertion.
     * 
     * @param assertion the assertion used to populate the user details record.
     */
    public Saml2UserDetails(Assertion assertion) throws MarshallingException {
        Assert.notNull(assertion, "no assertion provided");
        this.username = extractUsernameFrom(assertion);
        attributes = new Hashtable<String, List<String>>();
        marshaller = new Formatter();
        populateAttributesFromAssertion(assertion);
    }

    /**
     * Extracts the username from the assertion.
     * 
     * @param assertion the assertion to extract the username from.
     * @return the username or null if the username couldn't be found.
     */
    private String extractUsernameFrom(Assertion assertion) {
        try {
            Assert.notNull(assertion.getSubject(), "the assertion must have a subject");
            Assert.notNull(assertion.getSubject().getNameID(), "the assertion must have a name identifier");
            Assert.notNull(assertion.getSubject().getNameID().getValue(), "the assertion subject name must be valued");
            return assertion.getSubject().getNameID().getValue();
        }
        catch (IllegalArgumentException e) {
            logger.warn(e.getMessage());
            return null;
        }
    }

    /**
     * Populate's the user attributes using the attributes from the given SAML assertion.
     * 
     * @param assertion the SAML assertion.
     */
    private void populateAttributesFromAssertion(Assertion assertion) throws MarshallingException {
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                List<String> attributeValues = getAttributeValues(attribute.getName());
                attributeValues.addAll(extractAttributeValues(attribute));
            }
        }
    }

    /**
     * Extracts all of the attribute values from the given attribute.
     * 
     * @param attribute the attribute to get the values from.
     * @return a list of attribute values.
     * @throws MarshallingException if any of the attribute values can't be marshalled.
     */
    private List<String> extractAttributeValues(Attribute attribute) throws MarshallingException {
        List<String> list = new LinkedList<String>();
        for (XMLObject value : attribute.getAttributeValues()) {
            Element element = marshaller.marshall(value);
            list.add(element.getTextContent());
        }
        return list;
    }

    /**
     * Gets the list of attribute values for the given attribute name. If the attribute doesn't exist yet, it will be
     * created and an empty list will be returned.
     * 
     * @param name the attribute name.
     * @return the list of attribute values.
     */
    private List<String> getAttributeValues(String name) {
        List<String> attributeValues = attributes.get(name);
        if (attributeValues == null) {
            attributeValues = new LinkedList<String>();
            attributes.put(name, attributeValues);
        }
        return attributeValues;
    }

    /**
     * Returns the set of authorities that have been granted to the user. For the time being, we're only supporting
     * regular users.
     * 
     * @return the array of granted authorities.
     */
    public GrantedAuthority[] getAuthorities() {
        return new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_USER") };
    }

    /**
     * The user's password isn't supported or required by SAML, so this method simply returns a bogus password to
     * satisfy interface requirements.
     * 
     * @return a bogus password.
     */
    public String getPassword() {
        return "not applicable";
    }

    /**
     * The getter for the username property.
     * 
     * @return the username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Always returns true. We're relying on the identity provider to determine whether or not the user can be
     * authenticated, so any user who comes to us with a SAML assertion is assumed to have an active account.
     * 
     * @return true.
     */
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Always returns true. We're relying on the identity provider to determine whether or not the user can be
     * authenticated, so any user who comes to us with a SAML assertion is assumed to have an active account.
     * 
     * @return true.
     */
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Always returns true. We're relying on the identity provider to determine whether or not the user can be
     * authenticated, so any user who comes to us with a SAML assertion is assumed to have an active account.
     * 
     * @return true.
     */
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Always returns true. We're relying on the identity provider to determine whether or not the user can be
     * authenticated, so any user who comes to us with a SAML assertion is assumed to have an active account.
     * 
     * @return true.
     */
    public boolean isEnabled() {
        return true;
    }

    /**
     * Gets the set of attribute names.
     * 
     * @return the set of attribute names.
     */
    public Set<String> attributeNameSet() {
        return attributes.keySet();
    }

    /**
     * Gets an enumeration of attribute names.
     * 
     * @return an enumeration of attribute names.
     */
    public Enumeration<String> attributeNames() {
        return attributes.keys();
    }

    /**
     * Gets the value of the attribute with the given name.
     * 
     * @return the attribute value.
     */
    public List<String> getAttribute(String name) {
        return new LinkedList<String>(attributes.get(name));
    }

    /**
     * Sets an attribute.
     * 
     * @param name the name of the attribute.
     * @param value the value of the attribute.
     */
    public void addAttributeValue(String name, String value) {
        Assert.notNull(name);
        Assert.notNull(value);
        List<String> attributeValues = getAttributeValues(name);
        attributeValues.add(value);
    }

    /**
     * Determines whether or not another object is equal to this one.
     * 
     * @return true if the other object is equal to this one; false, otherwise.
     */
    public boolean equals(Object otherObject) {
        boolean equal = false;
        if (otherObject instanceof Saml2UserDetails) {
            Saml2UserDetails other = (Saml2UserDetails) otherObject;
            equal
                = !other.getUsername().equals(username) ? false
                : !other.attributesEqual(attributes)    ? false
                :                                         true;
        }
        return equal;
    }

    /**
     * Determines whether or not the given set of attributes is equal to our attribute set. The primary purpose of this
     * method is to make it easier to implement the equals method.
     * 
     * @param otherAttributes the other attributes to compare to ours.
     * @return true if the attribute sets are equal; false, otherwise.
     */
    public boolean attributesEqual(Hashtable<String, List<String>> otherAttributes) {
        return attributes.equals(otherAttributes);
    }

    /**
     * Returns the user's attributes.
     * 
     * @return an unmodifiable view of the user's attributes.
     */
    public Map<String, List<String>> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }
}
