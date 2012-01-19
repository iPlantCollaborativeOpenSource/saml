package org.iplantc.security;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests the user details.
 * 
 * @author Dennis Roberts
 */
public class Saml2UserDetailsTest {

    /**
     * The username to use for testing.
     */
    private static final String USERNAME = "nobody@iplantcollaborative.org";

    /**
     * A logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2UserDetailsTest.class);

    /**
     * The instance to use for testing.
     */
    private Saml2UserDetails instance;

    /**
     * Initializes each test.
     */
    @Before
    public void initialize() {
        instance = createUserDetails(USERNAME);
    }

    /**
     * Creates a new user details object with the given username and some default attributes.
     * 
     * @return the new user details.
     */
    private Saml2UserDetails createUserDetails(String username) {
        Saml2UserDetails userDetails = new Saml2UserDetails(username);
        userDetails.addAttributeValue("foo", "foo");
        userDetails.addAttributeValue("bar", "bar");
        userDetails.addAttributeValue("baz", "baz");
        return userDetails;
    }

    /**
     * Verifies that we can get the username.
     */
    @Test
    public void shouldGetUsername() {
        logger.debug("Verifying that we can get the username...");
        assertEquals(USERNAME, instance.getUsername());
    }

    /**
     * Verifies that we can add and retrieve attributes.
     */
    @Test
    public void shouldGetAttribute() {
        logger.debug("Verifying that we can add and retrieve attributes...");
        instance.addAttributeValue("eduPersonPrincipalName", USERNAME);
        List<String> expected = Arrays.asList(USERNAME);
        assertEquals(expected, instance.getAttribute("eduPersonPrincipalName"));
    }

    /**
     * Verifies that we can get the set of attribute names.
     */
    @Test
    public void shouldGetAttributeNameSet() {
        logger.debug("Verifying that we can get the set of attribute names...");
        Set<String> expected = new HashSet<String>(Arrays.asList("foo", "bar", "baz"));
        assertEquals(expected, instance.attributeNameSet());
    }

    /**
     * Verifies that we can get an enumeration of attribute names.
     */
    @Test
    public void shouldGetAttributeNames() {
        logger.debug("Verifying that we an get an enumeration of attribute names...");
        Set<String> expected = new HashSet<String>(Arrays.asList("foo", "bar", "baz"));
        assertEquals(expected, stringSetFromEnumeration(instance.attributeNames()));
    }

    /**
     * Verifies that we always get the same password.
     */
    @Test
    public void shouldGetBogusPassword() {
        logger.debug("Verifying that we always get the same password...");
        assertEquals("not applicable", instance.getPassword());
    }

    /**
     * Verifies that the account is never expired.
     */
    @Test
    public void shouldNotBeExpired() {
        logger.debug("Verifying that the account is never expired...");
        assertTrue(instance.isAccountNonExpired());
    }

    /**
     * Verifies that the account is never locked.
     */
    @Test
    public void shouldNotBeLocked() {
        logger.debug("Verifying that the account is never locked...");
        assertTrue(instance.isAccountNonLocked());
    }

    /**
     * Verifies that the account credentials are never expired.
     */
    @Test
    public void credentialsShouldNotBeExpired() {
        logger.debug("Verifying that the credentials are never expired...");
        assertTrue(instance.isCredentialsNonExpired());
    }

    /**
     * Verifies that the account is always enabled.
     */
    @Test
    public void credentialsShouldBeEnabled() {
        logger.debug("Verifying that the account is always enabled...");
        assertTrue(instance.isEnabled());
    }

    /**
     * Verifies that an attribute can have multiple attribute values.
     */
    @Test
    public void attributeShouldAcceptMultipleValues() {
        logger.debug("Verifying that an attribute can have multiple values...");
        instance.addAttributeValue("blarg", "foo");
        instance.addAttributeValue("blarg", "bar");
        instance.addAttributeValue("blarg", "baz");
        List<String> expected = Arrays.asList("foo", "bar", "baz");
        assertEquals(expected, instance.getAttribute("blarg"));
    }

    /**
     * Verifies that two equal user details objects are found to be equal.
     */
    @Test
    public void shouldDetectEqualObjects() {
        logger.debug("Verifying that two equal user details objects are found to be equal...");
        Saml2UserDetails otherInstance = createUserDetails(USERNAME);
        assertTrue(instance.equals(otherInstance));
    }

    /**
     * Verifies that two user details objects with different usernames are found to be unequal.
     */
    @Test
    public void shouldDetectDifferentUsernames() {
        logger.debug("Verifying that two user details objects with different usernames are found to be unequal...");
        Saml2UserDetails otherInstance = createUserDetails("somebody@iplantcollaborative.org");
        assertFalse(instance.equals(otherInstance));
    }

    /**
     * Verifies that two user details objects with different attributes are found to be unequal.
     */
    @Test
    public void shouldDetectDifferentAttributes() {
        logger.debug("Verifying that two user details objects with different attributes are found to be unequal...");
        Saml2UserDetails otherInstance = createUserDetails(USERNAME);
        otherInstance.addAttributeValue("some-attribute", "some-value");
        assertFalse(instance.equals(otherInstance));
    }

    /**
     * Verifies that two user details objects with different attribute values are found to be unequal.
     */
    @Test
    public void shouldDetectDifferentAttributeValues() {
        logger.debug("Verifying that equals() detects attributes with different values...");
        Saml2UserDetails otherInstance = createUserDetails(USERNAME);
        otherInstance.addAttributeValue("foo", "oof");
        assertFalse(instance.equals(otherInstance));
    }

    /**
     * converts an enumeration of strings to a set of strings.
     * 
     * @param enumeration the enumeration to convert.
     * @return the new set.
     */
    private Set<String> stringSetFromEnumeration(Enumeration<String> enumeration) {
        Set<String> retval = new HashSet<String>();
        while (enumeration.hasMoreElements()) {
            retval.add(enumeration.nextElement());
        }
        return retval;
    }
}
