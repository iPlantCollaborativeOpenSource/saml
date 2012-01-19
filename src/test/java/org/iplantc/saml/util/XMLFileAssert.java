package org.iplantc.saml.util;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;

import org.custommonkey.xmlunit.XMLAssert;
import org.custommonkey.xmlunit.XMLUnit;
import org.opensaml.common.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Provides some utility functions for comparing in-memory XML documents to XML files, with the caller only having to
 * specify the path to the XML file.  All file paths are expected to be relative to the test resource directory, which
 * is src/test/resources.
 *
 * @author Dennis Roberts
 */
public class XMLFileAssert extends XMLAssert {

    /**
     * The resource directory path elements.
     */
    static private final String[] RESOURCE_DIR_ELEMENTS = { "src", "test", "resources" };
    
    /**
     * The resource directory.  This is the directory that all file paths should be relative to.
     */
    static private final String RESOURCE_DIR = PathBuilder.buildPath(RESOURCE_DIR_ELEMENTS);

    /**
     * Verifies that the XML string provided in the second argument is equivalent to the XML document in the file
     * specified by the first argument.
     *
     * @param filename the path to the XML file, relative to the test resource directory.
     * @param actual a string containing the actual xml document to check.
     * @throws SAXException if an XML parsing error occurs.
     * @throws IOException if an I/O error occurs.
     */
    static public void assertXMLEqualToFile(String filename, String actual) throws SAXException, IOException {
        if (actual == null) {
            fail();
        }
        File path = new File(RESOURCE_DIR, filename);
        FileReader expectedReader = new FileReader(path);
        StringReader actualReader = new StringReader(actual);
        assertXMLEqual(expectedReader, actualReader);
    }
    
    /**
     * Verifies thta the XML element provided in the second argument is equivalent to the XML document in the file
     * specified by the first argument.
     * 
     * @param filename the path to the XML file, relative to the test resource directory.
     * @param actual the actual XML document to check.
     * @throws SAMLException if an XML parsing error occurs.
     * @throws IOException if an I/O error occurs.
     */
    static public void assertXMLEqualToFile(String filename, Element actual) throws SAXException, IOException {
        File path = new File(RESOURCE_DIR, filename);
        FileReader expectedReader = new FileReader(path);
        Document expectedDocument = XMLUnit.buildDocument(XMLUnit.newControlParser(), expectedReader);
        assertXMLEqual(expectedDocument, actual.getOwnerDocument());
    }
}
