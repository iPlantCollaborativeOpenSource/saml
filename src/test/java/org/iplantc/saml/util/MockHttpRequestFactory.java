package org.iplantc.saml.util;

public class MockHttpRequestFactory {
	/**
	 * Provides a mock HttpServletRequest that has the Shibboleth Environment Variables 
	 * set as session attributes.  
	 * 
	 * @return a instance of HttpServletRequest that has Shibboleth Environment Variables set
	 */
	public static MockHttpServletRequest getHttpRequestWithShibbolethEnvVariables() {
		MockHttpServletRequest mock = new MockHttpServletRequest();
		mock.setAttribute("HTTP_SHIB_SESSION_ID", "_c48fdff7369d38536ca87b741f4c35f7");
		mock.setAttribute("HTTP_SHIB_IDENTITY_PROVIDER", "https://gucumatz.iplantcollaborative.org/idp/shibboleth");
		mock.setAttribute("HTTP_SHIB_AUTHENTICATION_METHOD", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		mock.setAttribute("HTTP_SHIB_AUTHENTICATION_INSTANT", "2010-03-26T22:19:35.901Z");
		mock.setAttribute("HTTP_SHIB_AUTHNCONTEXT_CLASS", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		mock.setAttribute("HTTP_SHIB_AUTHNCONTEXT_DECL", "");
		mock.setAttribute("HTTP_SHIB_ASSERTION_COUNT", "");
		mock.setAttribute("HTTP_EPPN", "dennis@iplantcollaborative.org");
		// added - not part of original example
		mock.setAttribute("HTTP_AFFILIATION", "The iPlant Collaborative");
		// added - not part of original example
		mock.setAttribute("HTTP_UNSCOPED_AFFILIATION", "University of Arizona");	
		mock.setAttribute("HTTP_ENTITLEMENT", "");
		mock.setAttribute("HTTP_ASSURANCE", "");
		mock.setAttribute("HTTP_TARGETED_ID", "");
		mock.setAttribute("HTTP_PERSISTENT_ID", "https://gucumatz.iplantcollaborative.org/idp/shibboleth!https://dhcp-96870ab7.ece.arizona.edu/shibboleth!GpsEDgvMAeBMa/8dYqHtxMF4YbY=");
		mock.setAttribute("HTTP_SHIB_APPLICATION_ID", "default");
		mock.setAttribute("HTTP_REMOTE_USER", "");
		return mock;
	}
}
