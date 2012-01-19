package org.iplantc.saml;

import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds a SAML2 subject.  Note that the subject should not be modified after it has been marshalled.  Since there
 * aren't any methods to modify a subject after it's been created, however, no checking is done.  If any modification
 * methods are added in the future, some checks should be added.
 *
 * @author Dennis Roberts
 *
 * TODO modify class so that it only throws descendants of Saml2Exception.
 */
public class SubjectBuilder {
    
    /**
     * A factory to create various object builders.
     */
    private XMLObjectBuilderFactory builderFactory;
    
    /**
     * The subject that is being built.
     */
    private Subject subject;

    /**
     * The logger.
     */
    private final Logger logger = LoggerFactory.getLogger(SubjectBuilder.class);

    /**
     * Initializes a subject builder.
     * 
     * @param name the name of the subject.
     */
    public SubjectBuilder(String name) {
        Bootstrap.bootstrap();
        builderFactory = Configuration.getBuilderFactory();
        createSubject(name);
    }

    /**
     * Creates the new subject.
     *
     * @param name the name of the subject.
     */
    private void createSubject(String name) {
        subject = getSubjectBuilder().buildObject();
        NameID nameId = getNameIDBuilder().buildObject();
        nameId.setValue(name);
        nameId.setFormat(NameID.X509_SUBJECT);
        subject.setNameID(nameId);
        logger.debug("created new subject element {} for {}", subject, name);
    }

    /**
     * Obtains a subject builder from the builder factory. The purpose of this method is to limit the scope of the
     * SuppressWarnings annotation to just the statement that needs it.
     * 
     * @return the subject builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<Subject> getSubjectBuilder() {
        return (SAMLObjectBuilder<Subject>) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Obtains a name ID builder from the builder factory. The purpose of this method is to limit the scope of the
     * SuppresssWarnings annotation to just the statement that needs it.
     * 
     * @return the name ID builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<NameID> getNameIDBuilder() {
        return (SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
    }
    
    /**
     * The getter for the subject property.
     * 
     * @return the subject.
     */
    public Subject getSubject() {
        return subject;
    }
    
    /**
     * Converts the subject to an XML document.
     * 
     * @return the formatted subject.
     * @throws MarshallingException if the subject can't be formatted.
     */
    public String formatSubject() throws MarshallingException {
        logger.debug("formatting subject {}", subject);
        return new Formatter().format(subject);
    }
}
