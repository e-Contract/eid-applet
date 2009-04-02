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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.impl.AuthenticationDataMessageHandler;
import be.fedict.eid.applet.service.impl.HelloMessageHandler;
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
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test, SERIALNUMBER=" + userId, notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		byte[] salt = "salt".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);
		message.saltValue = salt;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		byte[] challenge = "challenge".getBytes();

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
										+ "Class")).andReturn(
						AuthenticationTestService.class.getName());
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
										+ "Class")).andReturn(
						AuditTestService.class.getName());

		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE))
				.andReturn(challenge);
		mockHttpSession
				.removeAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE);

		mockHttpSession
				.setAttribute(
						AuthenticationDataMessageHandler.AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE,
						userId);
		EasyMock.expect(mockHttpSession.getAttribute("eid")).andReturn(null);
		mockHttpSession.setAttribute(EasyMock.eq("eid"), EasyMock
				.isA(EIdData.class));

		// prepare
		EasyMock.replay(mockHttpSession, mockServletRequest, mockServletConfig);

		// operate
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, mockHttpSession);

		// verify
		EasyMock.verify(mockHttpSession, mockServletRequest, mockServletConfig);
		assertTrue(AuthenticationTestService.isCalled());
		assertEquals(userId, AuditTestService.getAuditUserId());
	}

	@Test
	public void testInvalidAuthenticationSignature() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test, SERIALNUMBER=" + userId, notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		byte[] salt = "salt".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);
		message.saltValue = salt;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		byte[] challenge = "challenge".getBytes();

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, "foobar-challenge".getBytes());
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
										+ "Class")).andReturn(
						AuthenticationTestService.class.getName());
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
										+ "Class")).andReturn(
						AuditTestService.class.getName());

		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE))
				.andReturn(challenge);
		mockHttpSession
				.removeAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE);

		String remoteAddress = "1.2.3.4";
		EasyMock.expect(mockServletRequest.getRemoteAddr()).andReturn(
				remoteAddress);

		// prepare
		EasyMock.replay(mockHttpSession, mockServletRequest, mockServletConfig);

		// operate
		this.testedInstance.init(mockServletConfig);

		try {
			this.testedInstance.handleMessage(message, httpHeaders,
					mockServletRequest, mockHttpSession);
			fail();
		} catch (SecurityException e) {
			// expected
		}

		// verify
		EasyMock.verify(mockHttpSession, mockServletRequest, mockServletConfig);
		assertFalse(AuthenticationTestService.isCalled());
		assertNull(AuditTestService.getAuditUserId());
		assertEquals(remoteAddress, AuditTestService.getAuditRemoteAddress());
		assertEquals(certificate, AuditTestService.getAuditClientCertificate());
	}

	@Test
	public void testHandleMessageWithoutAuditService() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test, SERIALNUMBER=" + userId, notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		byte[] salt = "salt".getBytes();

		AuthenticationDataMessage message = new AuthenticationDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);
		message.saltValue = salt;

		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);

		byte[] challenge = "challenge".getBytes();

		AuthenticationContract authenticationContract = new AuthenticationContract(
				salt, null, null, challenge);
		byte[] toBeSigned = authenticationContract.calculateToBeSigned();
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(toBeSigned);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME
										+ "Class")).andReturn(
						AuthenticationTestService.class.getName());
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME))
				.andReturn(null);
		EasyMock
				.expect(
						mockServletConfig
								.getInitParameter(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME
										+ "Class")).andReturn(null);

		EasyMock
				.expect(
						mockHttpSession
								.getAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE))
				.andReturn(challenge);
		mockHttpSession
				.removeAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE);

		mockHttpSession
				.setAttribute(
						AuthenticationDataMessageHandler.AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE,
						userId);
		EasyMock.expect(mockHttpSession.getAttribute("eid")).andReturn(null);
		mockHttpSession.setAttribute(EasyMock.eq("eid"), EasyMock
				.isA(EIdData.class));

		// prepare
		EasyMock.replay(mockHttpSession, mockServletRequest, mockServletConfig);

		// operate
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, mockHttpSession);

		// verify
		EasyMock.verify(mockHttpSession, mockServletRequest, mockServletConfig);
		assertTrue(AuthenticationTestService.isCalled());
		assertNull(AuditTestService.getAuditUserId());
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
