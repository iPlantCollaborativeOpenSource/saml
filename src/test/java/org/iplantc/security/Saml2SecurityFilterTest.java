package org.iplantc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;

import org.apache.xml.security.utils.Base64;
import org.iplantc.saml.AssertionBuilder;
import org.iplantc.saml.AssertionEncrypter;
import org.iplantc.saml.util.KeyLoader;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.ui.AbstractProcessingFilter;

/**
 * Unit tests for org.iplantc.security.Saml2SecurityFilterTest.
 * 
 * @author Dennis Roberts
 */
@SuppressWarnings("deprecation")
public class Saml2SecurityFilterTest implements ApplicationEventPublisher, AuthenticationManager, FilterChain,
        HttpServletRequest, HttpServletResponse, HttpSession
{

    /**
     * A logger for debugging messages.
     */
    private final Logger logger = LoggerFactory.getLogger(Saml2SecurityFilterTest.class);

    /**
     * The security filter used for testing.
     */
    private Saml2SecurityFilter instance;

    /**
     * The last event that was published.
     */
    private ApplicationEvent lastEventPublished = null;

    /**
     * True if doFilter was called.
     */
    private boolean doFilterCalled = false;

    /**
     * The HTTP session attributes.
     */
    private Map<String, Object> sessionAttributes = null;

    /**
     * True if the authentication should succeed for the current test.
     */
    private boolean authenticationShouldSucceedIfPossible = true;

    /**
     * Signs the assertion that is being built by the given assertion builder.
     * 
     * @param builder the builder that is being used to build the assertion.
     * @param keyAlias the alias of the key used to sign the assertion.
     * @throws Exception if an error occurs.
     */
    private void signAssertion(AssertionBuilder builder, String keyAlias) throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        X509Certificate certificate = keyLoader.loadCertificate(keyAlias);
        PrivateKey privateKey = keyLoader.loadPrivateKey(keyAlias);
        builder.signAssertion(certificate, privateKey, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    }

    /**
     * Creates a signed assertion.
     * 
     * @param signingKeyAlias the alias of the key used to sign the assertion.
     * @return the signed assertion.
     * @throws Exception if an error occurs.
     */
    private Assertion createSignedAssertion(String signingKeyAlias) throws Exception {
        AssertionBuilder builder = new AssertionBuilder();
        builder.setSubject("nobody@iplantcollaborative.org");
        builder.addAuthnMethod(AuthnContext.PASSWORD_AUTHN_CTX, "2010-03-10T22:13:18.732Z");
        signAssertion(builder, signingKeyAlias);
        return builder.getAssertion();
    }

    /**
     * Encrypts an assertion.
     * 
     * @param assertion the assertion to encrypt.
     * @return the encrypted assertion.
     * @throws Exception if an error occurs.
     */
    private String encryptAssertion(Assertion assertion, String encryptingKeyAlias) throws Exception {
        KeyLoader keyLoader = new KeyLoader();
        AssertionEncrypter encrypter = new AssertionEncrypter();
        encrypter.setPublicKey(keyLoader.loadCertificate(encryptingKeyAlias).getPublicKey());
        encrypter.setPublicKeyAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        encrypter.setSecretKeyAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
        return encrypter.encryptAssertion(assertion);
    }

    /**
     * Creates the assertion and adds it to the appropriate HTTP header.
     * 
     * @param signingKeyAlias the alias for the key used to sign the assertion.
     * @param encryptingKeyAlias the alias for the key used to encrypt the assertion.
     * @throws Exception if an error occurs.
     */
    private void createAssertionHeader(String signingKeyAlias, String encryptingKeyAlias) throws Exception {
        Assertion assertion = createSignedAssertion(signingKeyAlias);
        String encodedAssertion = Base64.encode(encryptAssertion(assertion, encryptingKeyAlias).getBytes());
        sessionAttributes.put("_iplant_auth", encodedAssertion);
    }

    /**
     * Creates the assertion using the default signing and encrypting keys and adds it to the appropriate HTTP header.
     * 
     * @throws Exception if an error occurs.
     */
    private void createAssertionHeader() throws Exception {
        createAssertionHeader("signing", "encrypting");
    }

    /**
     * Records a copy of an authentication request. This is a method stub used for testing.
     */
    public void publishEvent(ApplicationEvent event) {
        logger.debug("received a published event: {}", event);
        lastEventPublished = event;
    }

    /**
     * Imitates the processing of an authentication request. This is a method stub used for testing.
     * 
     * @param authentication the authentication request to process.
     * @return the processed authentication request or null to indicate that we can't process the request.
     * @throws AuthenticationException if the authentication fails.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        logger.debug("received an authentication request: {}", authentication);
        if (authenticationShouldSucceedIfPossible) {
            authentication.setAuthenticated(true);
            return authentication;
        }
        throw new BadCredentialsException("I don't know you; go away!");
    }

    /**
     * Records the fact that this subroutine was called. This is a method stub used for testing.
     * 
     * @param request the servlet request.
     * @param response the servlet response.
     * @throws IOException never.
     * @throws ServletException never.
     */
    public void doFilter(ServletRequest arg0, ServletResponse arg1) throws IOException, ServletException {
        doFilterCalled = true;
    }

    /**
     * Initializes each test.
     * 
     * @throws Exception if an error occurs.
     */
    @Before
    public void initialize() throws Exception {
        createSecurityFilter();
        lastEventPublished = null;
        doFilterCalled = false;
        sessionAttributes = new HashMap<String, Object>();
        authenticationShouldSucceedIfPossible = true;
    }

    /**
     * Creates the security filter to use in each test.
     * 
     * @throws Exception if an error occurs.
     */
    private void createSecurityFilter() throws Exception {
        instance = new Saml2SecurityFilter();
        instance.setApplicationEventPublisher(this);
        instance.setAuthenticationManager(this);
        instance.setKeyStorePath("src/test/resources/test.jceks");
        instance.setKeyStorePassword("changeit");
        instance.setKeyStoreType("JCEKS");
        instance.setKeyEncryptingKeyPairAlias("encrypting");
        instance.setKeyEncryptingKeyPairPassword("changeit");
        instance.setTrustedSigningCertificateAliases(Arrays.asList("signing", "signing2"));
        instance.afterPropertiesSet();
    }

    /**
     * Verifies that the initialization works when all of the required parameters are set.
     */
    @Test
    public void shouldInitialize() {
        logger.debug("Verifying that the initialization works when all required parameters are set...");
        assertNotNull(instance.getKeyStoreForTesting());
        assertNotNull(instance.getKeyEncryptingKeyPairForTesting());
        assertNotNull(instance.getTrustedSigningCertificatesForTesting());
        assertEquals(2, instance.getTrustedSigningCertificatesForTesting().size());
    }

    /**
     * Verifies that trying to set the application event publisher to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullApplicationEventPublisher() {
        logger.debug("Verifying that trying to set the event publisher to null results in an exception...");
        instance.setApplicationEventPublisher(null);
    }

    /**
     * Verifies that trying to set the authentication manager to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullAuthenticationManager() {
        logger.debug("Verifying that trying to set the authenticaiton manager to null results in an exception...");
        instance.setAuthenticationManager(null);
    }

    /**
     * Verifies that trying to set the keystore path to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyStorePath() {
        logger.debug("Verifying that trying to set the keystore path to null results in an exception...");
        instance.setKeyStorePath(null);
    }

    /**
     * Verifies that trying to set the keystore password to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyStorePassword() {
        logger.debug("Verifying that trying to set the keystore password to null results in an exception...");
        instance.setKeyStorePassword(null);
    }

    /**
     * Verifies that trying to set the keystore type to null results in an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyStoreType() {
        logger.debug("Verifying that trying to set the keystore type to null results in an exception...");
        instance.setKeyStoreType(null);
    }

    /**
     * Verifies that trying to set the key encrypting key pair alias to null causes an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyEncryptingKeyPairAlias() {
        logger.debug("Verifying that trying to set the key encrypting key pair alias to null causes an exception...");
        instance.setKeyEncryptingKeyPairAlias(null);
    }

    /**
     * Verifies that trying to set the key encrypting key pair password to null causes an exception.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullKeyEncryptingKeyPairPassword() {
        logger.debug("Verigying that an exception is thrown for a null key encrypting key pair password...");
        instance.setKeyEncryptingKeyPairPassword(null);
    }

    /**
     * Verifies that an exception is thrown for a null trusted signing certificate list.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowNullTrustedSigningCertificateAliasList() {
        logger.debug("Verifying that an exception is thrown for a null trusted signing certificate list...");
        instance.setTrustedSigningCertificateAliases(null);
    }

    /**
     * Verifies that an exception is thrown for an empty trusted signing certificate list.
     */
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowEmptyTrustedSigningCertificateAliasList() {
        logger.debug("Verifying that an exception is thrown for an empty trusted signing certificate list...");
        instance.setTrustedSigningCertificateAliases(new LinkedList<String>());
    }

    /**
     * Verifies that a valid assertion is accepted.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAcceptValidAssertion() throws Exception {
        logger.debug("Verifying that a valid assertion is accepted...");
        createAssertionHeader();
        instance.doFilterHttp(this, this, this);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertNull(sessionAttributes.get(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY));
        assertTrue(doFilterCalled);
        assertNotNull(lastEventPublished);
    }

    /**
     * Verifies that a failed authentication is rejected.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldRejectFailedAuthentication() throws Exception {
        logger.debug("Verifying that a failed authentication is rejected...");
        createAssertionHeader();
        authenticationShouldSucceedIfPossible = false;
        instance.doFilterHttp(this, this, this);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNotNull(sessionAttributes.get(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY));
        assertTrue(doFilterCalled);
        assertNull(lastEventPublished);
    }

    /**
     * Verifies that we get an exception if authentication fails and the security filter is configured to quit after a
     * failed authentication.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected = BadCredentialsException.class)
    public void shouldNotContinueAuthenticationIfNotSupposedTo() throws Exception {
        logger.debug("Verifying that authentication attempts cease when they're supposed to...");
        createAssertionHeader();
        authenticationShouldSucceedIfPossible = false;
        instance.setContinueFilterChainOnUnsuccessfulAuthentication(false);
        instance.doFilterHttp(this, this, this);
    }

    /**
     * Verifies that authentication fails if there's no assertion.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected = BadCredentialsException.class)
    public void shouldRejectAuthenticationRequestWithNoAssertion() throws Exception {
        logger.debug("Verifying that authentication fails if there's no assertion...");
        instance.setContinueFilterChainOnUnsuccessfulAuthentication(false);
        instance.doFilterHttp(this, this, this);
    }

    /**
     * Verifies that authentication fails if the assertion can't be decrypted.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected = BadCredentialsException.class)
    public void shouldNotContinueAuthenticationIfUnableToDecrypt() throws Exception {
        logger.debug("Verifying that authentication fails if the assertion can't be decrypted...");
        createAssertionHeader("signing", "signing");
        instance.setContinueFilterChainOnUnsuccessfulAuthentication(false);
        instance.doFilterHttp(this, this, this);
    }

    /**
     * Verifies that authentication fails if the assertion signature can't be verified.
     * 
     * @throws Exception if an error occurs.
     */
    @Test(expected = BadCredentialsException.class)
    public void shouldNotContinueAuthenticationIfUnableToVerifySignature() throws Exception {
        logger.debug("Verifying that authentication fails if the assertion signature can't be verified...");
        createAssertionHeader("encrypting", "encrypting");
        instance.setContinueFilterChainOnUnsuccessfulAuthentication(false);
        instance.doFilterHttp(this, this, this);
    }

    /**
     * Verifies that we can accept multiple signing certificates.
     * 
     * @throws Exception if an error occurs.
     */
    @Test
    public void shouldAcceptMultipleSigningCertificates() throws Exception {
        logger.debug("Verifying that we can accept multiple signing certificates...");
        createAssertionHeader("signing2", "encrypting");
        instance.doFilterHttp(this, this, this);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertNull(sessionAttributes.get(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY));
        assertTrue(doFilterCalled);
        assertNotNull(lastEventPublished);
    }

    /**
     * {@inheritDoc}
     */
    public String getAuthType() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getContextPath() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public Cookie[] getCookies() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public long getDateHeader(String arg0) {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public String getHeader(String name) {
        return (String) sessionAttributes.get(name);
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public Enumeration getHeaderNames() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public Enumeration getHeaders(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public int getIntHeader(String arg0) {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public String getMethod() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getPathInfo() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getPathTranslated() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getQueryString() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRemoteUser() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRequestURI() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public StringBuffer getRequestURL() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRequestedSessionId() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getServletPath() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public HttpSession getSession() {
        return this;
    }

    /**
     * {@inheritDoc}
     */
    public HttpSession getSession(boolean arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public Principal getUserPrincipal() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isRequestedSessionIdFromCookie() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isRequestedSessionIdFromURL() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isRequestedSessionIdFromUrl() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isRequestedSessionIdValid() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isUserInRole(String arg0) {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public Object getAttribute(String name) {
        return sessionAttributes.get(name);
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public Enumeration getAttributeNames() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getCharacterEncoding() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public int getContentLength() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public String getContentType() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public ServletInputStream getInputStream() throws IOException {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getLocalAddr() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getLocalName() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public int getLocalPort() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public Locale getLocale() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public Enumeration getLocales() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getParameter(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public Map getParameterMap() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public Enumeration getParameterNames() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String[] getParameterValues(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getProtocol() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public BufferedReader getReader() throws IOException {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRealPath(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRemoteAddr() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getRemoteHost() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public int getRemotePort() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public RequestDispatcher getRequestDispatcher(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getScheme() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String getServerName() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public int getServerPort() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isSecure() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public void removeAttribute(String arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void setAttribute(String name, Object value) {
        sessionAttributes.put(name, value);
    }

    /**
     * {@inheritDoc}
     */
    public void setCharacterEncoding(String arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void addCookie(Cookie arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void addDateHeader(String arg0, long arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public void addHeader(String arg0, String arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public void addIntHeader(String arg0, int arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public boolean containsHeader(String arg0) {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public String encodeRedirectURL(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String encodeRedirectUrl(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String encodeURL(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String encodeUrl(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public void sendError(int arg0) throws IOException {
    }

    /**
     * {@inheritDoc}
     */
    public void sendError(int arg0, String arg1) throws IOException {
    }

    /**
     * {@inheritDoc}
     */
    public void sendRedirect(String arg0) throws IOException {
    }

    /**
     * {@inheritDoc}
     */
    public void setDateHeader(String arg0, long arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public void setHeader(String arg0, String arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public void setIntHeader(String arg0, int arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public void setStatus(int arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void setStatus(int arg0, String arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public void flushBuffer() throws IOException {
    }

    /**
     * {@inheritDoc}
     */
    public int getBufferSize() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public ServletOutputStream getOutputStream() throws IOException {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public PrintWriter getWriter() throws IOException {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public boolean isCommitted() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public void reset() {
    }

    /**
     * {@inheritDoc}
     */
    public void resetBuffer() {
    }

    /**
     * {@inheritDoc}
     */
    public void setBufferSize(int arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void setContentLength(int arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void setContentType(String arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void setLocale(Locale arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public long getCreationTime() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public String getId() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public long getLastAccessedTime() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public int getMaxInactiveInterval() {
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public ServletContext getServletContext() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public HttpSessionContext getSessionContext() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public Object getValue(String arg0) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public String[] getValueNames() {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    public void invalidate() {
    }

    /**
     * {@inheritDoc}
     */
    public boolean isNew() {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public void putValue(String arg0, Object arg1) {
    }

    /**
     * {@inheritDoc}
     */
    public void removeValue(String arg0) {
    }

    /**
     * {@inheritDoc}
     */
    public void setMaxInactiveInterval(int arg0) {
    }
}
