/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.eid.applet.service.AppletServiceServlet;
import be.fedict.eid.applet.service.impl.handler.SignatureDataMessageHandler;
import be.fedict.eid.applet.service.spi.AddressDTO;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityDTO;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.SignatureDataMessage;

public class SignatureDataMessageHandlerTest {

	private static final Log LOG = LogFactory
			.getLog(SignatureDataMessageHandlerTest.class);

	private SignatureDataMessageHandler testedInstance;

	@BeforeClass
	public static void setUpClass() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new SignatureDataMessageHandler();
		SignatureTestService.reset();
	}

	@Test
	public void testHandleMessage() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);

		EasyMock.expect(mockServletConfig.getInitParameter("AuditService"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("AuditServiceClass"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("SignatureService"))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig.getInitParameter("SignatureServiceClass"))
				.andStubReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE))
				.andStubReturn(digestValue);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE))
				.andStubReturn("SHA-1");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		// prepare
		EasyMock.replay(mockServletConfig, mockHttpSession, mockServletRequest);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, mockHttpSession);

		// verify
		EasyMock.verify(mockServletConfig, mockHttpSession, mockServletRequest);
		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
	}

	@Test
	public void testHandleMessagePSS() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);

		EasyMock.expect(mockServletConfig.getInitParameter("AuditService"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("AuditServiceClass"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("SignatureService"))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig.getInitParameter("SignatureServiceClass"))
				.andStubReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE))
				.andStubReturn(digestValue);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE))
				.andStubReturn("SHA-1-PSS");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA/PSS", "BC");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		// prepare
		EasyMock.replay(mockServletConfig, mockHttpSession, mockServletRequest);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, mockHttpSession);

		// verify
		EasyMock.verify(mockServletConfig, mockHttpSession, mockServletRequest);
		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
	}

	@Test
	public void testHandleMessagePSS_SHA256() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);

		EasyMock.expect(mockServletConfig.getInitParameter("AuditService"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("AuditServiceClass"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("SignatureService"))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig.getInitParameter("SignatureServiceClass"))
				.andStubReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE))
				.andStubReturn(digestValue);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE))
				.andStubReturn("SHA-256-PSS");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		// prepare
		EasyMock.replay(mockServletConfig, mockHttpSession, mockServletRequest);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, mockHttpSession);

		// verify
		EasyMock.verify(mockServletConfig, mockHttpSession, mockServletRequest);
		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
	}

	@Test
	public void testHandleMessageWithAudit() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test,SERIALNUMBER=1234", notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);

		EasyMock.expect(mockServletConfig.getInitParameter("AuditService"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("AuditServiceClass"))
				.andStubReturn(AuditTestService.class.getName());
		EasyMock.expect(mockServletConfig.getInitParameter("SignatureService"))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig.getInitParameter("SignatureServiceClass"))
				.andStubReturn(SignatureTestService.class.getName());

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE))
				.andStubReturn(digestValue);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE))
				.andStubReturn("SHA-1");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(document);
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		// prepare
		EasyMock.replay(mockServletConfig, mockHttpSession, mockServletRequest);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		this.testedInstance.handleMessage(message, httpHeaders,
				mockServletRequest, mockHttpSession);

		// verify
		EasyMock.verify(mockServletConfig, mockHttpSession, mockServletRequest);
		assertEquals(signatureValue, SignatureTestService.getSignatureValue());
		assertEquals("1234", AuditTestService.getAuditSigningUserId());
	}

	@Test
	public void testHandleMessageInvalidSignature() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = MiscTestUtils.generateCertificate(
				keyPair.getPublic(), "CN=Test", notBefore, notAfter, null,
				keyPair.getPrivate(), true, 0, null, null);

		ServletConfig mockServletConfig = EasyMock
				.createMock(ServletConfig.class);
		Map<String, String> httpHeaders = new HashMap<String, String>();
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockServletRequest = EasyMock
				.createMock(HttpServletRequest.class);

		EasyMock.expect(mockServletConfig.getInitParameter("AuditService"))
				.andStubReturn(null);
		EasyMock.expect(mockServletConfig.getInitParameter("AuditServiceClass"))
				.andStubReturn(AuditTestService.class.getName());
		EasyMock.expect(mockServletConfig.getInitParameter("SignatureService"))
				.andStubReturn(null);
		EasyMock.expect(
				mockServletConfig.getInitParameter("SignatureServiceClass"))
				.andStubReturn(SignatureTestService.class.getName());

		EasyMock.expect(mockServletRequest.getRemoteAddr()).andStubReturn(
				"remote-address");

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] document = "hello world".getBytes();
		byte[] digestValue = messageDigest.digest(document);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_VALUE_SESSION_ATTRIBUTE))
				.andStubReturn(digestValue);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(SignatureDataMessageHandler.DIGEST_ALGO_SESSION_ATTRIBUTE))
				.andStubReturn("SHA-1");

		SignatureDataMessage message = new SignatureDataMessage();
		message.certificateChain = new LinkedList<X509Certificate>();
		message.certificateChain.add(certificate);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update("foobar-document".getBytes());
		byte[] signatureValue = signature.sign();
		message.signatureValue = signatureValue;

		// prepare
		EasyMock.replay(mockServletConfig, mockHttpSession, mockServletRequest);

		// operate
		AppletServiceServlet.injectInitParams(mockServletConfig,
				this.testedInstance);
		this.testedInstance.init(mockServletConfig);
		try {
			this.testedInstance.handleMessage(message, httpHeaders,
					mockServletRequest, mockHttpSession);
			fail();
		} catch (ServletException e) {
			LOG.debug("expected exception: " + e.getMessage());
			// verify
			EasyMock.verify(mockServletConfig, mockHttpSession,
					mockServletRequest);
			assertNull(SignatureTestService.getSignatureValue());
			assertEquals("remote-address",
					AuditTestService.getAuditSignatureRemoteAddress());
			assertEquals(certificate,
					AuditTestService.getAuditSignatureClientCertificate());
		}
	}

	public static class SignatureTestService implements SignatureService {

		private static byte[] signatureValue;

		public static void reset() {
			SignatureTestService.signatureValue = null;
		}

		public static byte[] getSignatureValue() {
			return SignatureTestService.signatureValue;
		}

		public String getFilesDigestAlgorithm() {
			return null;
		}

		public void postSign(byte[] signatureValue,
				List<X509Certificate> signingCertificateChain) {
			SignatureTestService.signatureValue = signatureValue;
		}

		public DigestInfo preSign(List<DigestInfo> digestInfos,
				List<X509Certificate> signingCertificateChain,
				IdentityDTO identity, AddressDTO address, byte[] photo)
				throws NoSuchAlgorithmException {
			return null;
		}
	}
}
