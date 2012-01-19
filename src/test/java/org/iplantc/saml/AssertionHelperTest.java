package org.iplantc.saml;

import static org.junit.Assert.*;
import static org.iplantc.saml.util.XMLFileAssert.assertXMLEqualToFile;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.iplantc.saml.AssertionDecrypter;
import org.iplantc.saml.Saml2Exception;
import org.iplantc.saml.util.AssertionHelper;
import org.iplantc.saml.util.KeyLoader;
import org.iplantc.saml.util.MockHttpRequestFactory;
import org.iplantc.saml.util.MockHttpServletRequest;
import org.iplantc.saml.util.RequestAttributes;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Unit tests for org.iplantc.saml.util.AssertionHelper
 * 
 * @author lenards
 *
 */
public class AssertionHelperTest {

	/**
     * A logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(AssertionHelperTest.class);
    
    private X509Certificate cert4Signing = null;
    private PrivateKey privKey4Signing = null;
    private PublicKey pubKey4Encrypt = null;
    private KeyPair decryptKeyPair = null;
    
    @Before
    public void init() {
    	// the current keystore for test has the following certs of interest: "signing", "encrypting"
        KeyLoader keyLoader;
		try {
			keyLoader = new KeyLoader();
	        cert4Signing = keyLoader.loadCertificate("signing");
	        privKey4Signing = keyLoader.loadPrivateKey("signing");
	        pubKey4Encrypt = keyLoader.loadCertificate("encrypting").getPublicKey();
	        decryptKeyPair = keyLoader.loadKeyPair("encrypting");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    private void sanityCheck() {
    	assertNotNull(cert4Signing);
    	assertNotNull(privKey4Signing);
    	assertNotNull(pubKey4Encrypt);
    	assertNotNull(decryptKeyPair);
    }

    private String marshalToXml(Assertion assertion) {
        String xml = null;
    	MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
  		try {
			Element assertionElement = marshaller.marshall(assertion);
			xml = XMLHelper.prettyPrintXML(assertionElement);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}
  		return xml;    	
    }    

	private Assertion decrypt(String encrypted) throws UnmarshallingException {
		AssertionDecrypter decrypter = new AssertionDecrypter(decryptKeyPair);
		Assertion assertion = decrypter.decryptAssertion(encrypted);
		return assertion;
	}
	
	private void validate(Assertion assertion) {
  		SignatureValidator signatureValidator = new SignatureValidator();
  		signatureValidator.addCredential(cert4Signing);
  		boolean valid = signatureValidator.isValid(assertion);
  		if (!valid) {
  			fail();
  		}		
	}
	
	/**
	 * Given the "known request attributes" provided in the MockHttpServletRequest, 
	 * verify that the AssertionHelper can create an encoded, encrypted SAML2 
	 * assertion represented by a string. 
	 * 
	 * Known request attributes are currently defined in org.iplantc.saml.util.RequestAttributes
	 */
    @Test
    public void test_create_encoded_assertion() {
    	sanityCheck();
    	MockHttpServletRequest request = MockHttpRequestFactory.getHttpRequestWithShibbolethEnvVariables();
		try {
			String encodedAssertion = AssertionHelper.createEncodedAssertion(
					request, cert4Signing, privKey4Signing, pubKey4Encrypt);
			assertTrue(encodedAssertion != null && !encodedAssertion.isEmpty());
			// dump out the encoded, encrypted assertion
			logger.debug("encoded-assertion=>\t" + encodedAssertion);
			
			String encrypted = new String(Base64.decode(encodedAssertion));
			
			Assertion assertion = decrypt(encrypted);
			// quick check to see if the subject is the HTTP_EPPN we set it to be
			assertTrue(assertion.getSubject().getNameID().getValue()
					.equals(request.getAttribute(RequestAttributes.EDUPERSON).toString()));
			// marshal over to xml 
            String xml = marshalToXml(assertion);
            // is it what we expected? 
            assertXMLEqualToFile("SamlAssertionCreatedFromHttpRequestDefaults.xml", xml);
      		// is it valid?
      		validate(assertion);
		} catch (Saml2Exception e) {
			e.printStackTrace();
			fail();
		} catch (MarshallingException e) {
			e.printStackTrace();
			fail();
		} catch (UnmarshallingException e) {
			e.printStackTrace();
			fail();
		} catch (SAXException e) {
			e.printStackTrace();
			fail();
		} catch (IOException e) {
			e.printStackTrace();
			fail();
		} finally {
			// ... whew
		}
    }

    /**
     * Similar to test_create_encoded_assertion - but tests overloaded version of 
     * AssertionHelper.createEncodedAssertion() that takes a KeyPair instead of 
     * a PublicKey for encryption. 
     * 
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Test
    public void test_create_encoded_assertion_with_encrypt_keypair() throws GeneralSecurityException, IOException {
    	sanityCheck();
    	MockHttpServletRequest request = MockHttpRequestFactory.getHttpRequestWithShibbolethEnvVariables();
    	KeyLoader keyLoader = new KeyLoader();
    	KeyPair keyPair = keyLoader.loadKeyPair("encrypting");
		try {
			String encodedAssert = AssertionHelper.createEncodedAssertion(
					request, cert4Signing, privKey4Signing, keyPair);
			assertTrue(encodedAssert != null && !encodedAssert.isEmpty());
			String encrypted = new String(Base64.decode(encodedAssert));
			Assertion assertion = decrypt(encrypted);
            String xml = marshalToXml(assertion);
            // is it what we expected? 
            assertXMLEqualToFile("SamlAssertionCreatedFromHttpRequestDefaults.xml", xml);
      		// is it valid?            
            validate(assertion);
    	} catch (Saml2Exception e) {
			e.printStackTrace();
			fail();
		} catch (MarshallingException e) {
			e.printStackTrace();
			fail();
		} catch (UnmarshallingException e) {
			e.printStackTrace();
			fail();
		} catch (SAXException e) {
			e.printStackTrace();
			fail();
		} 
    }

    /**
     * Verifies that erroneous http request attributes do not get included in the SAML
     * assertion.  We only want our set of known request attributes to be included.  
     * 
     * @throws Saml2Exception
     * @throws MarshallingException
     * @throws UnmarshallingException
     * @throws SAXException
     * @throws IOException
     */
    @Test
	public void test_verify_extra_request_attributes_not_included_in_assertion()
			throws Saml2Exception, MarshallingException,
			UnmarshallingException, SAXException, IOException {
    	sanityCheck();
    	MockHttpServletRequest request = MockHttpRequestFactory.getHttpRequestWithShibbolethEnvVariables();
    	request.setAttribute("HTTP_SOMETHING_AWESOME", "650");
    	request.setAttribute("HTTP_ERRONOUS_VALUE", "lenards:iplantcollaborative:org:bio5:org:arizona:edu");
		String encodedAssertion = AssertionHelper.createEncodedAssertion(
				request, cert4Signing, privKey4Signing, decryptKeyPair);
		String encrypted = new String(Base64.decode(encodedAssertion));
		Assertion assertion = decrypt(encrypted);
		// it should be exactly the same as other tests for positive assertion creation
        assertXMLEqualToFile("SamlAssertionCreatedFromHttpRequestDefaults.xml", marshalToXml(assertion));
        // and it should still validate 
        validate(assertion);
    }
    
    /**
     * Remove the two affiliation attributes from the http request and verify that they 
     * are *not* included in the assertion created. 
     */
    @Test
    public void test_empty_known_attributes_not_included_in_assertion() {
    	sanityCheck();
    	MockHttpServletRequest request = MockHttpRequestFactory.getHttpRequestWithShibbolethEnvVariables();
    	request.setAttribute("HTTP_AFFILIATION", "");         
    	request.setAttribute("HTTP_UNSCOPED_AFFILIATION", "");
    		String encodedAssertion;
			try {
				encodedAssertion = AssertionHelper.createEncodedAssertion(request, cert4Signing, privKey4Signing, pubKey4Encrypt);
	    		String encrypted = new String(Base64.decode(encodedAssertion));
	    		Assertion assertion = decrypt(encrypted);
	    		// it should not include either affiliation or unscoped affiliation like the default tested assertion
	    		assertXMLEqualToFile("SamlAssertionCreatedFromHttpRequestWithoutAffiliation.xml", marshalToXml(assertion));
	    		// and it should still validate
	    		validate(assertion);
			} catch (Saml2Exception e) {
				e.printStackTrace();
				fail();
			} catch (MarshallingException e) {
				e.printStackTrace();
				fail();
			} catch (UnmarshallingException e) {
				e.printStackTrace();
				fail();
			} catch (SAXException e) {
				e.printStackTrace();
				fail();
			} catch (IOException e) {
				e.printStackTrace();
				fail();
			}
    }
    
    /**
     * Confirm exception thrown when necessary known request attributes are set to empty values. 
     * 
     * @throws Saml2Exception
     * @throws MarshallingException
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_failure_when_known_auth_attributes_empty_in_http_request() throws Saml2Exception, MarshallingException {
    	sanityCheck();
    	MockHttpServletRequest request = MockHttpRequestFactory.getHttpRequestWithShibbolethEnvVariables();
    	request.setAttribute("HTTP_SHIB_AUTHENTICATION_METHOD", "");
        request.setAttribute("HTTP_SHIB_AUTHENTICATION_INSTANT", "");
        request.setAttribute("HTTP_EPPN", "");    	
        String encodedAssertion = AssertionHelper.createEncodedAssertion(request, cert4Signing, privKey4Signing, pubKey4Encrypt);
        assertNotNull(encodedAssertion);
    }

    /**
     * Confirm exception thrown when necessary known request attributes are missing. 
     *  
     * @throws Saml2Exception
     * @throws MarshallingException
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_failure_when_known_auth_attributes_missing_from_http_request() throws Saml2Exception, MarshallingException {
    	sanityCheck();
    	MockHttpServletRequest request = MockHttpRequestFactory.getHttpRequestWithShibbolethEnvVariables();
    	request.removeAttribute("HTTP_SHIB_AUTHENTICATION_METHOD");
        request.removeAttribute("HTTP_SHIB_AUTHENTICATION_INSTANT");
        request.removeAttribute("HTTP_EPPN");    	
        String encodedAssertion = AssertionHelper.createEncodedAssertion(request, cert4Signing, privKey4Signing, pubKey4Encrypt);
        assertNotNull(encodedAssertion);   	
    }
}
