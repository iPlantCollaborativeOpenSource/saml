package org.iplantc.saml.util;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Methods used to read and write entire files at once.
 *
 * @author Dennis Roberts
 */
public class FileSlurper {

    /**
     * The resource directory path elements.
     */
    static private final String[] RESOURCE_DIR_ELEMENTS = { "src", "test", "resources" };

    /**
     * The maximum number of characters to read at one time.
     */
    static private final int MAX_READ_LEN = 1024;

    /**
     * The resource directory. This is the directory that all file paths should be relative to.
     */
    static private final String RESOURCE_DIR = PathBuilder.buildPath(RESOURCE_DIR_ELEMENTS);

    /**
     * Reads the contents of the file with the given name. The file name should be a path that is relative to the
     * project's test resource directory.
     * 
     * @param filename the name of the file.
     * @return a string containing the file contents.
     * @throws IOException if an I/O error occurs.
     */
    public String slurp(String filename) throws IOException {
        return getFileContents(new File(RESOURCE_DIR, filename));
    }

    /**
     * Writes the given string to the given file.
     *
     * @param filename the name of the file.
     * @param contents a string containing the new file contents.
     * @throws IOException if an I/O error occurs.
     */
    public void unslurp(String filename, String contents) throws IOException {
        PrintWriter out = null;
        try {
            out = new PrintWriter(new FileWriter(new File(RESOURCE_DIR, filename)));
            out.print(contents);
        }
        finally {
            if (out != null) {
                out.close();
            }
        }
    }

    /**
     * Fetches the contents of a file.
     * 
     * @param path the path to the file.
     * @return a string containing the contents of the file.
     * @throws IOException if an I/O error occurs.
     */
    private String getFileContents(File path) throws IOException {
        FileReader in = null;
        try {
            in = new FileReader(path);
            return getFileContents(in);
        }
        finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /**
     * Fetches the contents of a file.
     * 
     * @param in the FileReader to read data from.
     * @throws IOException if an I/O error occurs.
     */
    private String getFileContents(FileReader in) throws IOException {
        StringBuilder builder = new StringBuilder();
        char[] buffer = new char[MAX_READ_LEN];
        while (true) {
            int charsRead = in.read(buffer, 0, MAX_READ_LEN);
            if (charsRead < 0) {
                break;
            }
            builder.append(buffer, 0, charsRead);
        }
        return builder.toString();
    }
}
