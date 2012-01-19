package org.iplantc.saml;

import static org.iplantc.saml.util.XMLFileAssert.*;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that we can successfully build subjects.
 *
 * @author Dennis Roberts
 */
public class SubjectBuilderTest {

    /**
     * The logger to use for debug messages.
     */
    private final Logger logger = LoggerFactory.getLogger(SubjectBuilderTest.class);

    /**
     * Verifies that we can successfully build a subject.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldFormatSubject() throws Exception {
        logger.debug("Verifying that we can build a subject...");
        SubjectBuilder builder = new SubjectBuilder("nobody@iplantcollaborative.org");
        assertXMLEqualToFile("SamlSubject.xml", builder.formatSubject());
    }
}
