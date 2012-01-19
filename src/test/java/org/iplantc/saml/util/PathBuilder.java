package org.iplantc.saml.util;

import java.io.File;

/**
 * Provides a convenient way to build File Paths.
 *
 * @author Dennis Roberts
 */
public class PathBuilder {

    /**
     * Builds a path from the given path components.
     *
     * @param elements the array of path elements.
     * @return the path.
     */
    public static String buildPath(String[] elements) {
        StringBuilder builder = new StringBuilder();
        if (elements.length > 0) {
            builder.append(elements[0]);
            for (int i = 1; i < elements.length; i++) {
                builder.append(File.separator);
                builder.append(elements[i]);
            }
        }
        return builder.toString();
    }
}
