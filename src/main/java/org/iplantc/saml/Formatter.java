package org.iplantc.saml;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Provides a simple way to convert SAML objects to formatted XML documents.
 * 
 * @author Dennis Roberts
 * 
 *         TODO modify class so that it only throws descendants of Saml2Exception.
 */
public class Formatter {

    /**
     * A logger for informational and error messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Formatter.class);

    /**
     * Creates a new SAML2 formatter. At this time the constructor only ensures that the OpenSAML library is
     * bootstrapped properly. Strictly speaking, this shouldn't be necessary by the time we get here, but the method
     * call is cheap, and it doesn't hurt to be safe.
     */
    public Formatter() {
        Bootstrap.bootstrap();
    }

    /**
     * Converts a SAML object to an XML element.
     * 
     * @param samlObject the SAML object.
     * @return an XML element.
     * @throws MarshallingException if the object can't be converted for any reason.
     */
    public Element marshall(XMLObject samlObject) throws MarshallingException {
        logger.debug("marshalling SAML object {}", samlObject);
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(samlObject);
        return marshaller.marshall(samlObject);
    }

    /**
     * Unmarshalls a formatted XML document.
     *
     * @param xml the XML document to unmarshall.
     * @return the unmarshalled XML object.
     * @throws UnmarshallingException if the document can't be parsed or unmarshalled.
     */
    public XMLObject unmarshall(String xml) throws UnmarshallingException {
        logger.debug("unmarshalling XML string {}", xml);
        try {
            BasicParserPool parser = new BasicParserPool();
            Document document = parser.parse(new StringReader(xml));
            return unmarshall(document.getDocumentElement());
        }
        catch (XMLParserException e) {
            String msg = "unable to parse XML string " + xml;
            logger.error(msg);
            throw new UnmarshallingException(msg);
        }
    }

    /**
     * Unmarshalls an XML element.
     *
     * @param element the element to unmarshall.
     * @return the unmarshalled XML object.
     * @throws UnmarshallingException if the element can't be unmarshalled.
     */
    public XMLObject unmarshall(Element element) throws UnmarshallingException {
        logger.debug("unmarshalling XML element {}", element);
        Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(element);
        return unmarshaller.unmarshall(element);
    }

    /**
     * Converts a SAML object to a formatted XML document.
     * 
     * @param samlObject the object to convert.
     * @return the formatted XML document as a string.
     * @throws MarshallingException if the object can't be converted for any reason.
     */
    public String format(XMLObject samlObject) throws MarshallingException {
        logger.debug("formatting SAML object {}", samlObject);
        return format(marshall(samlObject));
    }

    /**
     * Converts an XML element to a string.
     * 
     * @param element the XML element.
     * @return the formatted XML document.
     * @throws MarshallingException if the element can't be converted.
     */
    public String format(Element element) throws MarshallingException {
        logger.debug("transforming XML element {}", element);
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            StreamResult result = new StreamResult(new StringWriter());
            transformer.transform(new DOMSource(element), result);
            return result.getWriter().toString();
        }
        catch (TransformerException e) {
            String msg = "unable to format the SAML object";
            logger.error(msg, e);
            throw new MarshallingException(msg, e);
        }
    }
}
