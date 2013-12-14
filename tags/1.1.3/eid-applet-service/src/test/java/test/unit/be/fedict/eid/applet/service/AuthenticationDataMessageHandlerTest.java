/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.unit.be.fedict.eid.applet.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.eid.applet.service.AppletServiceServlet;
import be.fedict.eid.applet.service.impl.AuthenticationChallenge;
import be.fedict.eid.applet.service.impl.UserIdentifierUtil;
import be.fedict.eid.applet.service.impl.handler.AuthenticationDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.HelloMessageHandler;
import be.fedict.eid.applet.service.impl.handler.IdentityDataMessageHandler;
import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.eid.applet.shared.AuthenticationContract;
import be.fedict.eid.applet.shared.AuthenticationDataMessage;

public class AuthenticationDataMessageHandlerTest {

	private AuthenticationDataMessageHandler testedInstance;

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new AuthenticationDataMessageHandler();
		AuthenticationTestService.reset();
		AuditTestService.reset();
	}

	@Test
	public void testHandleMessage() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test, SERIALNUMBER=" + userId,
				notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null,
				null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge
				.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, sessionId, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuthenticationTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuditTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME
								+ "Class")).andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE
								+ "Class")).andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES))
				.andReturn(null);

		EasyMock.expect(
				mockServletRequest
						.getAttribute("javax.servlet.request.ssl_session"))
				.andStubReturn(new String(Hex.encodeHex(sessionId)));
		EasyMock.expect(mockServletRequest.getRemoteAddr()).andStubReturn(
				"1.2.3.4");

		// prepare
		EasyMock.replay(mockServletRequest, mockServletConfig);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, testHttpSession);

		// verify
		EasyMock.verify(mockServletRequest, mockServletConfig);
		assertTrue(AuthenticationTestService.isCalled());
		assertEquals(userId, AuditTestService.getAuditUserId());
		assertEquals(userId, testHttpSession.getAttribute("eid.identifier"));
	}

	@Test
	public void testHandleMessageNRCID() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test, SERIALNUMBER=" + userId,
				notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null,
				null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge
				.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, sessionId, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuthenticationTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuditTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.andStubReturn(null);
		String nrcidSecret = "112233445566778899AABBCCDDEEFF00112233445566778899";
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.andStubReturn(nrcidSecret);
		String nrcidAppId = "my-app-id";
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.andStubReturn(nrcidAppId);
		String nrcidOrgId = "my-org-id";
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.andStubReturn(nrcidOrgId);

		EasyMock.expect(
				mockServletRequest
						.getAttribute("javax.servlet.request.ssl_session"))
				.andStubReturn(new String(Hex.encodeHex(sessionId)));
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME
								+ "Class")).andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE
								+ "Class")).andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES))
				.andReturn(null);
		EasyMock.expect(mockServletRequest.getRemoteAddr()).andStubReturn(
				"1.2.3.4");
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(null);

		// prepare
		EasyMock.replay(mockServletRequest, mockServletConfig);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, testHttpSession);

		// verify
		EasyMock.verify(mockServletRequest, mockServletConfig);
		assertTrue(AuthenticationTestService.isCalled());

		String nrcid = UserIdentifierUtil.getNonReversibleCitizenIdentifier(
				userId, nrcidOrgId, nrcidAppId, nrcidSecret);

		assertTrue(nrcid.equals(AuditTestService.getAuditUserId()));
		assertTrue(nrcid.equals(testHttpSession.getAttribute("eid.identifier")));
	}

	@Test
	public void testHandleMessageExpiredChallenge() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test, SERIALNUMBER=" + userId,
				notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null,
				null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge
				.generateChallenge(testHttpSession);

		Thread.sleep(1000); // > 1 ms

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, sessionId, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.andReturn("1"); // 1 ms
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuthenticationTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME
								+ "Class")).andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuditTestService.class.getName());
		EasyMock.expect(mockServletRequest.getRemoteAddr()).andStubReturn(
				"remote-address");

		EasyMock.expect(
				mockServletRequest
						.getAttribute("javax.servlet.request.ssl_session"))
				.andStubReturn(new String(Hex.encodeHex(sessionId)));
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE
								+ "Class")).andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(null);

		// prepare
		EasyMock.replay(mockServletRequest, mockServletConfig);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		try {
			this.testedInstance.handleMessage(message, httpHeaders,
					mockServletRequest, testHttpSession);
			fail();
		} catch (ServletException e) {
			// verify
			EasyMock.verify(mockServletRequest, mockServletConfig);
			assertNull(AuditTestService.getAuditUserId());
			assertNull(testHttpSession.getAttribute("eid.identifier"));
			assertEquals(certificate,
					AuditTestService.getAuditClientCertificate());
			assertEquals("remote-address",
					AuditTestService.getAuditRemoteAddress());
		}
	}

	@Test
	public void testInvalidAuthenticationSignature() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test, SERIALNUMBER=" + userId,
				notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null,
				null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		AuthenticationChallenge.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, sessionId, null,
				"foobar-challenge".getBytes());
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuthenticationTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuditTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME
								+ "Class")).andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE
								+ "Class")).andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(null);

		EasyMock.expect(
				mockServletRequest
						.getAttribute("javax.servlet.request.ssl_session"))
				.andStubReturn(new String(Hex.encodeHex(sessionId)));

		String remoteAddress = "1.2.3.4";
		EasyMock.expect(mockServletRequest.getRemoteAddr()).andReturn(
				remoteAddress);

		// prepare
		EasyMock.replay(mockServletRequest, mockServletConfig);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);

		try {
			this.testedInstance.handleMessage(message, httpHeaders,
					mockServletRequest, testHttpSession);
			fail();
		} catch (SecurityException e) {
			// expected
		}

		// verify
		EasyMock.verify(mockServletRequest, mockServletConfig);
		assertFalse(AuthenticationTestService.isCalled());
		assertNull(AuditTestService.getAuditUserId());
		assertEquals(remoteAddress, AuditTestService.getAuditRemoteAddress());
		assertEquals(certificate, AuditTestService.getAuditClientCertificate());
		assertNull(testHttpSession.getAttribute("eid.identifier"));
	}

	@Test
	public void testHandleMessageWithoutAuditService() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test, SERIALNUMBER=" + userId,
				notBefore, notAfter, null, keyPair.getPrivate(), true, 0, null,
				null);

		byte[] salt = "salt".getBytes();
		byte[] sessionId = "session-id".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.authnCert = certificate;
		message.saltValue = salt;
		message.sessionId = sessionId;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession testHttpSession = new HttpTestSession();
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		byte[] challenge = AuthenticationChallenge
				.generateChallenge(testHttpSession);

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, sessionId, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(
				AuthenticationTestService.class.getName());
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_SECRET_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME
								+ "Class")).andStubReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE
								+ "Class")).andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_ORG_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.NRCID_APP_ID_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME
								+ "Class")).andReturn(null);

		EasyMock.expect(
				mockServletRequest
						.getAttribute("javax.servlet.request.ssl_session"))
				.andStubReturn(new String(Hex.encodeHex(sessionId)));
		EasyMock.expect(
				mockServletConfig
						.getInitParameter(IdentityDataMessageHandler.INCLUDE_DATA_FILES))
				.andReturn(null);
		EasyMock.expect(mockServletRequest.getRemoteAddr()).andStubReturn(
				"1.2.3.4");

		// prepare
		EasyMock.replay(mockServletRequest, mockServletConfig);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, testHttpSession);

		// verify
		EasyMock.verify(mockServletRequest, mockServletConfig);
		assertTrue(AuthenticationTestService.isCalled());
		assertNull(AuditTestService.getAuditUserId());
		assertEquals(userId, testHttpSession.getAttribute("eid.identifier"));
	}

	public static class AuthenticationTestService implements
			AuthenticationService {

		private static boolean called;

		public static void reset() {
			AuthenticationTestService.called = false;
		}

		public static boolean isCalled() {
			return AuthenticationTestService.called;
		}

		private static final Log LOG = LogFactory
				.getLog(AuthenticationTestService.class);

		public void validateCertificateChain(
				List<X509Certificate> certificateChain)
				throws SecurityException {
			LOG.debug("validate certificate chain");
			AuthenticationTestService.called = true;
		}
	}
}
