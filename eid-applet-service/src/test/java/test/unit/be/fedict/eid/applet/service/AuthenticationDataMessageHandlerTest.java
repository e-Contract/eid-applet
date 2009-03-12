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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.impl.AuthenticationDataMessageHandler;
import be.fedict.eid.applet.service.impl.HelloMessageHandler;
import be.fedict.eid.applet.service.spi.AuditService;
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
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test, SERIALNUMBER=" + userId, notBefore, notAfter, null,
				keyPair.getPrivate(), true, 0, null, null);

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
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test, SERIALNUMBER=" + userId, notBefore, notAfter, null,
				keyPair.getPrivate(), true, 0, null, null);

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
	}

	@Test
	public void testHandleMessageWithoutAuditService() throws Exception {
		// setup
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test, SERIALNUMBER=" + userId, notBefore, notAfter, null,
				keyPair.getPrivate(), true, 0, null, null);

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

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private X509Certificate generateCertificate(PublicKey subjectPublicKey,
			String subjectDn, DateTime notBefore, DateTime notAfter,
			X509Certificate issuerCertificate, PrivateKey issuerPrivateKey,
			boolean caFlag, int pathLength, String crlUri, String ocspUri)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		String signatureAlgorithm = "SHA1withRSA";
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		X509Principal issuerDN;
		if (null != issuerCertificate) {
			issuerDN = new X509Principal(issuerCertificate
					.getSubjectX500Principal().toString());
		} else {
			issuerDN = new X509Principal(subjectDn);
		}
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));
		PublicKey issuerPublicKey;
		issuerPublicKey = subjectPublicKey;
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		if (caFlag) {
			if (-1 == pathLength) {
				certificateGenerator.addExtension(
						X509Extensions.BasicConstraints, false,
						new BasicConstraints(true));
			} else {
				certificateGenerator.addExtension(
						X509Extensions.BasicConstraints, false,
						new BasicConstraints(pathLength));
			}
		}

		if (null != crlUri) {
			GeneralName gn = new GeneralName(
					GeneralName.uniformResourceIdentifier, new DERIA5String(
							crlUri));
			GeneralNames gns = new GeneralNames(new DERSequence(gn));
			DistributionPointName dpn = new DistributionPointName(0, gns);
			DistributionPoint distp = new DistributionPoint(dpn, null, null);
			certificateGenerator.addExtension(
					X509Extensions.CRLDistributionPoints, false,
					new DERSequence(distp));
		}

		if (null != ocspUri) {
			GeneralName ocspName = new GeneralName(
					GeneralName.uniformResourceIdentifier, ocspUri);
			AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
					X509ObjectIdentifiers.ocspAccessMethod, ocspName);
			certificateGenerator.addExtension(
					X509Extensions.AuthorityInfoAccess.getId(), false,
					authorityInformationAccess);
		}

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new AuthorityKeyIdentifier(info);
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

	public static class AuditTestService implements AuditService {

		private static final Log LOG = LogFactory
				.getLog(AuditTestService.class);

		private static String auditUserId;

		private static String auditRemoteAddress;

		public static void reset() {
			AuditTestService.auditUserId = null;
			AuditTestService.auditRemoteAddress = null;
		}

		public static String getAuditUserId() {
			return AuditTestService.auditUserId;
		}

		public static String getAuditRemoteAddress() {
			return AuditTestService.auditRemoteAddress;
		}

		public void authenticated(String userId) {
			LOG.debug("authenticated: " + userId);
			AuditTestService.auditUserId = userId;
		}

		public void authenticationError(String remoteAddress) {
			LOG.debug("authentication error: " + remoteAddress);
			AuditTestService.auditRemoteAddress = remoteAddress;
		}
	}
}
