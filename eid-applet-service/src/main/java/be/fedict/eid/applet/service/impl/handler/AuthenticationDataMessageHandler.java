/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

package be.fedict.eid.applet.service.impl.handler;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.util.encoders.Hex;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.EIdCertsData;
import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.impl.AuthenticationChallenge;
import be.fedict.eid.applet.service.impl.RequestContext;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.impl.UserIdentifierUtil;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;
import be.fedict.eid.applet.service.spi.AuditService;
import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.eid.applet.service.spi.CertificateSecurityException;
import be.fedict.eid.applet.service.spi.ChannelBindingService;
import be.fedict.eid.applet.service.spi.ExpiredCertificateSecurityException;
import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.applet.service.spi.RevokedCertificateSecurityException;
import be.fedict.eid.applet.service.spi.TrustCertificateSecurityException;
import be.fedict.eid.applet.shared.AuthenticationContract;
import be.fedict.eid.applet.shared.AuthenticationDataMessage;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;

/**
 * Authentication data message protocol handler.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(AuthenticationDataMessage.class)
public class AuthenticationDataMessageHandler implements
		MessageHandler<AuthenticationDataMessage> {

	public static final String AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE = "eid.identifier";

	public static String PLAIN_TEXT_DIGEST_ALGO_OID = "2.16.56.1.2.1.3.1";

	private static final Log LOG = LogFactory
			.getLog(AuthenticationDataMessageHandler.class);

	@InitParam(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuditService> auditServiceLocator;

	@InitParam(HelloMessageHandler.CHANNEL_BINDING_SERVICE)
	private ServiceLocator<ChannelBindingService> channelBindingServiceLocator;

	@InitParam(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME)
	private String hostname;

	@InitParam(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME)
	private InetAddress inetAddress;

	@InitParam(CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME)
	private Long maxMaturity;

	private X509Certificate serverCertificate;

	@InitParam(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME)
	private boolean sessionIdChannelBinding;

	public static final String AUTHN_SERVICE_INIT_PARAM_NAME = "AuthenticationService";

	public static final String AUDIT_SERVICE_INIT_PARAM_NAME = "AuditService";

	public static final String CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME = "ChallengeMaxMaturity";

	public static final String NRCID_SECRET_INIT_PARAM_NAME = "NRCIDSecret";

	public static final String NRCID_ORG_ID_INIT_PARAM_NAME = "NRCIDOrgId";

	public static final String NRCID_APP_ID_INIT_PARAM_NAME = "NRCIDAppId";

	@InitParam(NRCID_SECRET_INIT_PARAM_NAME)
	private String nrcidSecret;

	@InitParam(NRCID_ORG_ID_INIT_PARAM_NAME)
	private String nrcidOrgId;

	@InitParam(NRCID_APP_ID_INIT_PARAM_NAME)
	private String nrcidAppId;

	@InitParam(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	public Object handleMessage(AuthenticationDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("authentication data message received");

		if (null == message.authnCert) {
			/*
			 * Can be the case for future (Kids) eID cards that have some
			 * certificates missing.
			 */
			String msg = "authentication certificate not present";
			LOG.warn(msg);
			throw new ServletException(msg);
		}
		byte[] signatureValue = message.signatureValue;
		LOG.debug("authn signing certificate subject: "
				+ message.authnCert.getSubjectX500Principal());
		PublicKey signingKey = message.authnCert.getPublicKey();

		if (this.sessionIdChannelBinding) {
			checkSessionIdChannelBinding(message, request);
			if (null == this.serverCertificate) {
				LOG.warn("adviced to use in combination with server certificate channel binding");
			}
		}

		ChannelBindingService channelBindingService = this.channelBindingServiceLocator
				.locateService();
		if (null != this.serverCertificate || null != channelBindingService) {
			LOG.debug("using server certificate channel binding");
		}

		if (false == this.sessionIdChannelBinding
				&& null == this.serverCertificate
				&& null == channelBindingService) {
			LOG.warn("not using any secure channel binding");
		}

		byte[] challenge;
		try {
			challenge = AuthenticationChallenge.getAuthnChallenge(session,
					this.maxMaturity);
		} catch (SecurityException e) {
			AuditService auditService = this.auditServiceLocator
					.locateService();
			if (null != auditService) {
				String remoteAddress = request.getRemoteAddr();
				auditService.authenticationError(remoteAddress,
						message.authnCert);
			}
			throw new ServletException("security error: " + e.getMessage(), e);
		}

		byte[] serverCertificateClientPOV = null;
		try {
			if (null != message.serverCertificate) {
				serverCertificateClientPOV = message.serverCertificate
						.getEncoded();
			}
		} catch (CertificateEncodingException e) {
			throw new ServletException("server cert decoding error: "
					+ e.getMessage(), e);
		}
		/*
		 * We validate the authentication contract using the client-side
		 * communicated server SSL certificate in case of secure channel
		 * binding.
		 */
		AuthenticationContract authenticationContract = new AuthenticationContract(
				message.saltValue, this.hostname, this.inetAddress,
				message.sessionId, serverCertificateClientPOV, challenge);
		byte[] toBeSigned;
		try {
			toBeSigned = authenticationContract.calculateToBeSigned();
		} catch (IOException e) {
			throw new ServletException("IO error: " + e.getMessage(), e);
		}

		try {
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(signingKey);
			signature.update(toBeSigned);
			boolean result = signature.verify(signatureValue);
			if (false == result) {
				AuditService auditService = this.auditServiceLocator
						.locateService();
				if (null != auditService) {
					String remoteAddress = request.getRemoteAddr();
					auditService.authenticationError(remoteAddress,
							message.authnCert);
				}
				throw new SecurityException("authn signature incorrect");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException("algo error");
		} catch (InvalidKeyException e) {
			throw new SecurityException("authn key error");
		} catch (SignatureException e) {
			throw new SecurityException("signature error");
		}

		RequestContext requestContext = new RequestContext(session);
		String transactionMessage = requestContext.getTransactionMessage();
		if (null != transactionMessage) {
			LOG.debug("verifying TransactionMessage signature");
			byte[] transactionMessageSignature = message.transactionMessageSignature;
			if (null == transactionMessageSignature) {
				throw new SecurityException(
						"missing TransactionMessage signature");
			}
			try {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, signingKey);
				byte[] signatureDigestInfoValue = cipher
						.doFinal(transactionMessageSignature);
				ASN1InputStream aIn = new ASN1InputStream(
						signatureDigestInfoValue);
				DigestInfo signatureDigestInfo = new DigestInfo(
						(ASN1Sequence) aIn.readObject());
				if (false == PLAIN_TEXT_DIGEST_ALGO_OID
						.equals(signatureDigestInfo.getAlgorithmId()
								.getObjectId().getId())) {
					throw new SecurityException(
							"TransactionMessage signature algo OID incorrect");
				}
				if (false == Arrays.equals(transactionMessage.getBytes(),
						signatureDigestInfo.getDigest())) {
					throw new SecurityException(
							"signed TransactionMessage incorrect");
				}
				LOG.debug("TransactionMessage signature validated");
			} catch (Exception e) {
				LOG.error("error verifying TransactionMessage signature", e);
				AuditService auditService = this.auditServiceLocator
						.locateService();
				if (null != auditService) {
					String remoteAddress = request.getRemoteAddr();
					auditService.authenticationError(remoteAddress,
							message.authnCert);
				}
				throw new SecurityException(
						"error verifying TransactionMessage signature: "
								+ e.getMessage());
			}
		}

		/*
		 * Secure channel binding verification.
		 */
		if (null != channelBindingService) {
			X509Certificate serverCertificate = channelBindingService
					.getServerCertificate();
			if (null == serverCertificate) {
				LOG.warn("could not verify secure channel binding as the server does not know its identity yet");
			} else {
				if (false == serverCertificate
						.equals(message.serverCertificate)) {
					AuditService auditService = this.auditServiceLocator
							.locateService();
					if (null != auditService) {
						String remoteAddress = request.getRemoteAddr();
						auditService.authenticationError(remoteAddress,
								message.authnCert);
					}
					throw new SecurityException(
							"secure channel binding identity mismatch");
				}
				LOG.debug("secure channel binding verified");
			}
		} else {
			if (null != this.serverCertificate) {
				if (false == this.serverCertificate
						.equals(message.serverCertificate)) {
					AuditService auditService = this.auditServiceLocator
							.locateService();
					if (null != auditService) {
						String remoteAddress = request.getRemoteAddr();
						auditService.authenticationError(remoteAddress,
								message.authnCert);
					}
					throw new SecurityException(
							"secure channel binding identity mismatch");
				}
				LOG.debug("secure channel binding verified");
			}
		}

		AuthenticationService authenticationService = this.authenticationServiceLocator
				.locateService();
		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		certificateChain.add(message.authnCert);
		certificateChain.add(message.citizenCaCert);
		certificateChain.add(message.rootCaCert);
		try {
			authenticationService.validateCertificateChain(certificateChain);
		} catch (ExpiredCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
		} catch (RevokedCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_REVOKED);
		} catch (TrustCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_NOT_TRUSTED);
		} catch (CertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE);
		} catch (Exception e) {
			/*
			 * We don't want to depend on the full JavaEE profile in this
			 * artifact.
			 */
			if ("javax.ejb.EJBException".equals(e.getClass().getName())) {
				Exception exception;
				try {
					Method getCausedByExceptionMethod = e.getClass().getMethod(
							"getCausedByException", new Class[] {});
					exception = (Exception) getCausedByExceptionMethod.invoke(
							e, new Object[] {});
				} catch (Exception e2) {
					LOG.debug("error: " + e.getMessage(), e);
					throw new SecurityException(
							"error retrieving the root cause: "
									+ e2.getMessage());
				}
				if (exception instanceof ExpiredCertificateSecurityException) {
					return new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
				}
				if (exception instanceof RevokedCertificateSecurityException) {
					return new FinishedMessage(ErrorCode.CERTIFICATE_REVOKED);
				}
				if (exception instanceof TrustCertificateSecurityException) {
					return new FinishedMessage(
							ErrorCode.CERTIFICATE_NOT_TRUSTED);
				}
				if (exception instanceof CertificateSecurityException) {
					return new FinishedMessage(ErrorCode.CERTIFICATE);
				}
			}
			throw new SecurityException("authn service error: "
					+ e.getMessage());
		}

		String userId = UserIdentifierUtil.getUserId(message.authnCert);
		if (null != this.nrcidSecret) {
			userId = UserIdentifierUtil.getNonReversibleCitizenIdentifier(
					userId, this.nrcidOrgId, this.nrcidAppId, this.nrcidSecret);
		}
		/*
		 * Some people state that you cannot use the national register number
		 * without hashing. Problem is that hashing introduces hash collision
		 * problems. The probability is very low, but what if it's your leg
		 * they're cutting of because of a patient mismatch based on the SHA1 of
		 * your national register number?
		 */

		/*
		 * Push authenticated used Id into the HTTP session.
		 */
		session.setAttribute(AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE,
				userId);

		EIdData eidData = (EIdData) session
				.getAttribute(IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE);
		if (null == eidData) {
			eidData = new EIdData();
			session.setAttribute(
					IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE, eidData);
		}
		eidData.identifier = userId;

		AuditService auditService = this.auditServiceLocator.locateService();
		if (null != auditService) {
			auditService.authenticated(userId);
		}

		boolean includeIdentity = requestContext.includeIdentity();
		boolean includeAddress = requestContext.includeAddress();
		boolean includeCertificates = requestContext.includeCertificates();
		boolean includePhoto = requestContext.includePhoto();

		/*
		 * Also process the identity data in case it was requested.
		 */
		if (includeIdentity) {
			if (null == message.identityData) {
				throw new ServletException(
						"identity data not included while requested");
			}
		}
		if (includeAddress) {
			if (null == message.addressData) {
				throw new ServletException(
						"address data not included while requested");
			}
		}
		if (includePhoto) {
			if (null == message.photoData) {
				throw new ServletException(
						"photo data not included while requested");
			}
		}
		IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
				.locateService();
		if (null != identityIntegrityService) {
			if (null == message.rrnCertificate) {
				throw new ServletException(
						"national registry certificate not included while requested");
			}
			List<X509Certificate> rrnCertificateChain = new LinkedList<X509Certificate>();
			rrnCertificateChain.add(message.rrnCertificate);
			rrnCertificateChain.add(message.rootCaCert);
			identityIntegrityService
					.checkNationalRegistrationCertificate(rrnCertificateChain);
			PublicKey rrnPublicKey = message.rrnCertificate.getPublicKey();
			if (includeIdentity) {
				if (null == message.identitySignatureData) {
					throw new ServletException(
							"identity signature data not included while requested");
				}
				verifySignature(message.identitySignatureData, rrnPublicKey,
						request, message.identityData);
			}
			if (includeAddress) {
				if (null == message.addressSignatureData) {
					throw new ServletException(
							"address signature data not included while requested");
				}
				byte[] addressFile = trimRight(message.addressData);
				verifySignature(message.addressSignatureData, rrnPublicKey,
						request, addressFile, message.identitySignatureData);
			}
		}
		if (includeIdentity) {
			Identity identity = TlvParser.parse(message.identityData,
					Identity.class);
			if (false == UserIdentifierUtil.getUserId(message.authnCert)
					.equals(identity.nationalNumber)) {
				throw new ServletException("national number mismatch");
			}
			session.setAttribute(
					IdentityDataMessageHandler.IDENTITY_SESSION_ATTRIBUTE,
					identity);
			eidData.identity = identity;
			auditService = this.auditServiceLocator.locateService();
			if (null != auditService) {
				auditService.identified(identity.nationalNumber);
			}
		}
		if (includeAddress) {
			Address address = TlvParser.parse(message.addressData,
					Address.class);
			session.setAttribute(
					IdentityDataMessageHandler.ADDRESS_SESSION_ATTRIBUTE,
					address);
			eidData.address = address;
		}
		if (includePhoto) {
			if (includeIdentity) {
				byte[] expectedPhotoDigest = eidData.identity.photoDigest;
				byte[] actualPhotoDigest = digestPhoto(message.photoData);
				if (false == Arrays.equals(expectedPhotoDigest,
						actualPhotoDigest)) {
					throw new ServletException("photo digest incorrect");
				}
			}
			session.setAttribute(
					IdentityDataMessageHandler.PHOTO_SESSION_ATTRIBUTE,
					message.photoData);
			eidData.photo = message.photoData;
		}
		if (includeCertificates) {
			if (includeIdentity) {
				eidData.certs = new EIdCertsData();
				eidData.certs.authn = message.authnCert;
				eidData.certs.ca = message.citizenCaCert;
				eidData.certs.root = message.rootCaCert;
				eidData.certs.sign = message.signCert;
			}
			session.setAttribute(
					IdentityDataMessageHandler.AUTHN_CERT_SESSION_ATTRIBUTE,
					message.authnCert);
			session.setAttribute(
					IdentityDataMessageHandler.CA_CERT_SESSION_ATTRIBUTE,
					message.citizenCaCert);
			session.setAttribute(
					IdentityDataMessageHandler.ROOT_CERT_SESSION_ATTRIBTUE,
					message.rootCaCert);
			session.setAttribute(
					IdentityDataMessageHandler.SIGN_CERT_SESSION_ATTRIBUTE,
					message.signCert);
		}

		return new FinishedMessage();
	}

	private byte[] trimRight(byte[] addressFile) {
		int idx;
		for (idx = 0; idx < addressFile.length; idx++) {
			if (0 == addressFile[idx]) {
				break;
			}
		}
		byte[] result = new byte[idx];
		System.arraycopy(addressFile, 0, result, 0, idx);
		return result;
	}

	private byte[] digestPhoto(byte[] photoFile) {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA1 error: " + e.getMessage(), e);
		}
		byte[] photoDigest = messageDigest.digest(photoFile);
		return photoDigest;
	}

	private void verifySignature(byte[] signatureData, PublicKey publicKey,
			HttpServletRequest request, byte[]... data) throws ServletException {
		Signature signature;
		try {
			signature = Signature.getInstance("SHA1withRSA");
		} catch (NoSuchAlgorithmException e) {
			throw new ServletException("algo error: " + e.getMessage(), e);
		}
		try {
			signature.initVerify(publicKey);
		} catch (InvalidKeyException e) {
			throw new ServletException("key error: " + e.getMessage(), e);
		}
		try {
			for (byte[] dataItem : data) {
				signature.update(dataItem);
			}
			boolean result = signature.verify(signatureData);
			if (false == result) {
				AuditService auditService = this.auditServiceLocator
						.locateService();
				if (null != auditService) {
					String remoteAddress = request.getRemoteAddr();
					auditService.identityIntegrityError(remoteAddress);
				}
				throw new ServletException("signature incorrect");
			}
		} catch (SignatureException e) {
			throw new ServletException("signature error: " + e.getMessage(), e);
		}
	}

	private void checkSessionIdChannelBinding(
			AuthenticationDataMessage message, HttpServletRequest request) {
		LOG.debug("using TLS session Id channel binding");
		byte[] sessionId = message.sessionId;
		/*
		 * Next is Tomcat specific.
		 */
		String actualSessionId = (String) request
				.getAttribute("javax.servlet.request.ssl_session");
		if (null == actualSessionId) {
			/*
			 * Servlet specs v3.0
			 */
			actualSessionId = (String) request
					.getAttribute("javax.servlet.request.ssl_session_id");
		}
		if (null == actualSessionId) {
			LOG.warn("could not verify the SSL session identifier");
			return;
		}
		if (false == Arrays.equals(sessionId, Hex.decode(actualSessionId))) {
			LOG.warn("SSL session Id mismatch");
			LOG.debug("signed SSL session Id: "
					+ new String(Hex.encode(sessionId)));
			LOG.debug("actual SSL session Id: " + actualSessionId);
			throw new SecurityException("SSL session Id mismatch");
		}
		LOG.debug("SSL session identifier checked");
	}

	public void init(ServletConfig config) throws ServletException {
		String channelBindingServerCertificate = config
				.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE);
		if (null != channelBindingServerCertificate) {
			File serverCertificateFile = new File(
					channelBindingServerCertificate);
			if (false == serverCertificateFile.exists()) {
				throw new ServletException("server certificate not found: "
						+ serverCertificateFile);
			}
			byte[] encodedServerCertificate;
			try {
				encodedServerCertificate = FileUtils
						.readFileToByteArray(serverCertificateFile);
			} catch (IOException e) {
				throw new ServletException("error reading server certificate: "
						+ e.getMessage(), e);
			}
			this.serverCertificate = getCertificate(encodedServerCertificate);
		}
	}

	private X509Certificate getCertificate(byte[] certData) {
		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException("cert factory error: " + e.getMessage(),
					e);
		}
		try {
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(certData));
			return certificate;
		} catch (CertificateException e) {
			throw new RuntimeException("certificate decoding error: "
					+ e.getMessage(), e);
		}
	}
}
