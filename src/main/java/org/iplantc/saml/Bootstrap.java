package org.iplantc.saml;

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

/**
 * Ensures that OpenSAML has been bootstrapped properly. This class uses the singleton pattern in an effort to make life
 * easier for clients of this library. The idea is that the constructor for every class in this library will call the
 * bootstrap method in this class. If the library has already been bootstrapped then nothing is done. Otherwise, the
 * OpenSAML library is bootstrapped using its default configuration, which will work for us.
 * 
 * @author Dennis Roberts
 */
public class Bootstrap {

    /**
     * The single instance of this class.
     */
    private static Bootstrap instance = null;

    /**
     * Bootstraps the OpenSAML library using the default configuration.
     */
    private Bootstrap() {
        try {
            DefaultBootstrap.bootstrap();
        }
        catch (ConfigurationException e) {
            String msg = "unable to load the default OpenSAML configuration";
            throw new RuntimeException(msg, e);
        }
    }

    /**
     * Bootstraps the OpenSAML library using the default configuration if it hasn't been done already.
     */
    public static void bootstrap() {
        if (instance == null) {
            instance = new Bootstrap();
        }
    }

    /**
     * Returns the single instance of this class or null if no instance has been created yet. This method is intended to
     * be used for testing.
     * 
     * @return the instance or a null pointer.
     */
    public static Bootstrap getInstance() {
        return instance;
    }

    /**
     * Clears the single instance of this class if there is one. This method is intended to be used for testing.
     */
    public static void clearInstance() {
        instance = null;
    }
}
