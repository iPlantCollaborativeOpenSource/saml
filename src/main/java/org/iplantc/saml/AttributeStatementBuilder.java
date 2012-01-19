package org.iplantc.saml;

import javax.xml.namespace.QName;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides methods to add attributes to an attribute statement. The attribute statement may be modified until it is
 * marshalled (that is, until it has been converted to its XML representation). After the attribute statement has been
 * marshalled any attempt to modify it will result in a Saml2Exception.
 * 
 * @author Dennis Roberts
 * 
 * TODO modify class so that it only throws descendants of Sam2Exception.
 */
public class AttributeStatementBuilder {

    /**
     * A factory to create various object builders.
     */
    private XMLObjectBuilderFactory builderFactory;

    /**
     * The attribute statement that is being built.
     */
    private AttributeStatement attributeStatement;

    /**
     * The logger.
     */
    private final Logger logger = LoggerFactory.getLogger(AttributeStatementBuilder.class);

    /**
     * Creates a new attribute statement builder for the given attribute statement.
     */
    public AttributeStatementBuilder() {
        Bootstrap.bootstrap();
        builderFactory = Configuration.getBuilderFactory();
        attributeStatement = getAttributeStatementBuilder().buildObject();
        logger.debug("created attribute statement {}", attributeStatement);
    }

    /**
     * Getter for the attribute statement property.
     * 
     * @return the attribute statement.
     */
    public AttributeStatement getAttributeStatement() {
        return attributeStatement;
    }

    /**
     * Obtains an attribute statement builder from the builder factory. The purpose of this method is to limit the scope
     * of the SuppressWarnings annotation to just the statement that needs it.
     * 
     * @return the attribute statement builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<AttributeStatement> getAttributeStatementBuilder() {
        return (SAMLObjectBuilder<AttributeStatement>) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Obtains an attribute builder from the builder factory. The purpose of this method is to limit the scope of the
     * SuppressWarnings annotation to just the statement that needs it.
     * 
     * @return the attribute builder.
     */
    @SuppressWarnings("unchecked")
    private SAMLObjectBuilder<Attribute> getAttributeBuilder() {
        return (SAMLObjectBuilder<Attribute>) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Obtains an XML schema string builder from the builder factory. The purpose of this method is to limit the scope
     * of the SuppressWarnings directive to just the statement that needs it.
     * 
     * @return the XML schema string builder.
     */
    @SuppressWarnings("unchecked")
    private XMLObjectBuilder<XSString> getXSStringBuilder() {
        return (XMLObjectBuilder<XSString>) builderFactory.getBuilder(XSString.TYPE_NAME);
    }

    /**
     * Creates an XML schema string.
     * 
     * @param name the name of the string.
     * @return the SML schema string.
     */
    private XSString createXSString(QName name) {
        return getXSStringBuilder().buildObject(name, XSString.TYPE_NAME);
    }

    /**
     * Verifies that the attribute statement hasn't been marshalled already. An attribute statement is marshalled any
     * time the assertion is signed or encrypted.
     * 
     * @throws Saml2Exception if the attribute statement has already been marshalled.
     */
    private void verifyNotMarshalled() throws Saml2Exception {
        if (attributeStatement.getDOM() != null) {
            String msg = "illegal attempt to modify an attribute statement that has been signed or encrypted";
            logger.error(msg);
            throw new Saml2Exception(msg);
        }
    }

    /**
     * Adds a string attribute to the attribute statement.
     * 
     * @param name the name of the attribute.
     * @param format the format of the attribute.
     * @param value the value of the attribute.
     * @see <a href="http://www.incommonfederation.org/attributesummary.html">InCommon Federation Attribute Summary</a>
     *      for more information about common attributes.
     * @throws Saml2Exception if the attribute statement has already been marshalled.
     */
    public void addStringAttribute(String name, String format, String value) throws Saml2Exception {
        verifyNotMarshalled();
        Attribute attribute = getAttributeBuilder().buildObject();
        attribute.setName(name);
        attribute.setNameFormat(format);
        XSString stringValue = createXSString(AttributeValue.DEFAULT_ELEMENT_NAME);
        stringValue.setValue(value);
        attribute.getAttributeValues().add(stringValue);
        attributeStatement.getAttributes().add(attribute);
        logger.debug("Added attribute ({} : {} : {}) to attribute statement {}",
                new Object[] { name, format, value, attributeStatement });
    }

    /**
     * Converts the atrribute statement to an XML document.
     * 
     * @return the formatted attribute statement.
     * @throws MarshallingException if the attribute statement can't be formatted.
     */
    public String formatAttributeStatement() throws MarshallingException {
        logger.debug("formatting attribute statement {}", attributeStatement);
        return new Formatter().format(attributeStatement);
    }
}
