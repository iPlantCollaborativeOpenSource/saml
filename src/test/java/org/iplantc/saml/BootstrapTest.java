package org.iplantc.saml;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Verifies that we can Bootstrap the OpenSAML library.
 * 
 * @author Dennis Roberts
 */
public class BootstrapTest {

    /**
     * Ensures that each test begins with no bootstrap instance.
     */
    @Before
    public void initialize() {
        Bootstrap.clearInstance();
    }

    /**
     * Verifies that the instance is initially null.
     */
    @Test
    public void instanceShouldInitiallyBeNull() {
        assertNull(Bootstrap.getInstance());
    }

    /**
     * Verifies that the instance is created when the bootstrap method is called.
     */
    @Test
    public void instanceShouldBeCreatedWhenBootstrapIsCalled() {
        Bootstrap.bootstrap();
        assertNotNull(Bootstrap.getInstance());
    }
    
    /**
     * Verifies that the instance is not created twice.
     */
    @Test
    public void instanceShouldNotBeCreatedTwice() {
        assertNull(Bootstrap.getInstance());
        Bootstrap.bootstrap();
        Bootstrap instance = Bootstrap.getInstance();
        assertNotNull(instance);
        Bootstrap.bootstrap();
        assertEquals(instance, Bootstrap.getInstance());
    }
}
