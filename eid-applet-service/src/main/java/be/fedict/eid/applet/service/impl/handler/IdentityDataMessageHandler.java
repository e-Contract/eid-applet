/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 * Copyright (C) 2009 Frank Cornelis.
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
import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.EIdCertsData;
import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.impl.RequestContext;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;
import be.fedict.eid.applet.service.spi.AuditService;
import be.fedict.eid.applet.service.spi.CertificateSecurityException;
import be.fedict.eid.applet.service.spi.ExpiredCertificateSecurityException;
import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.applet.service.spi.RevokedCertificateSecurityException;
import be.fedict.eid.applet.service.spi.TrustCertificateSecurityException;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.IdentityDataMessage;

/**
 * Message handler for the identity data message.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(IdentityDataMessage.class)
public class IdentityDataMessageHandler implements
		MessageHandler<IdentityDataMessage> {

	private static final Log LOG = LogFactory
			.getLog(IdentityDataMessageHandler.class);

	public static final String IDENTITY_SESSION_ATTRIBUTE = "eid.identity";

	public static final String ADDRESS_SESSION_ATTRIBUTE = "eid.address";

	public static final String PHOTO_SESSION_ATTRIBUTE = "eid.photo";

	public static final String EID_SESSION_ATTRIBUTE = "eid";

	public static final String EID_CERTS_SESSION_ATTRIBUTE = "eid.certs";

	public static final String AUTHN_CERT_SESSION_ATTRIBUTE = "eid.certs.authn";

	public static final String SIGN_CERT_SESSION_ATTRIBUTE = "eid.certs.sign";

	public static final String CA_CERT_SESSION_ATTRIBUTE = "eid.certs.ca";

	/**
	 * Please use ROOT_CERT_SESSION_ATTRIBUTE instead.
	 */
	public static final String ROOT_CERT_SESSION_ATTRIBTUE = "eid.certs.root";

	public static final String ROOT_CERT_SESSION_ATTRIBUTE = "eid.certs.root";

	public static final String SKIP_NATIONAL_NUMBER_CHECK_INIT_PARAM_NAME = "SkipNationalNumberCheck";

	public static final String INCLUDE_DATA_FILES = "IncludeDataFiles";

	public static final String EID_DATA_IDENTITY_SESSION_ATTRIBUTE = "eid.data.identity";

	public static final String EID_DATA_ADDRESS_SESSION_ATTRIBUTE = "eid.data.address";

	@InitParam(SKIP_NATIONAL_NUMBER_CHECK_INIT_PARAM_NAME)
	private boolean skipNationalNumberCheck;

	@InitParam(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuditService> auditServiceLocator;

	@InitParam(INCLUDE_DATA_FILES)
	private boolean includeDataFiles;

	public Object handleMessage(IdentityDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("received identity data");

		LOG.debug("identity file size: " + message.idFile.length);
		// parse the identity files
		Identity identity = TlvParser.parse(message.idFile, Identity.class);

		RequestContext requestContext = new RequestContext(session);
		boolean includeAddress = requestContext.includeAddress();
		boolean includeCertificates = requestContext.includeCertificates();
		boolean includePhoto = requestContext.includePhoto();

		/*
		 * Check whether the answer is in-line with what we expected.
		 */
		Address address;
		if (null != message.addressFile) {
			LOG.debug("address file size: " + message.addressFile.length);
			if (false == includeAddress) {
				throw new ServletException(
						"Address included while not requested");
			}
			/*
			 * Address file can be null.
			 */
			address = TlvParser.parse(message.addressFile, Address.class);
		} else {
			if (true == includeAddress) {
				throw new ServletException(
						"Address not included while requested");
			}
			address = null;
		}

		X509Certificate authnCert = null;
		X509Certificate signCert = null;
		X509Certificate caCert = null;
		X509Certificate rootCert = null;
		if (includeCertificates) {
			if (null == message.authnCertFile) {
				throw new ServletException(
						"authn cert not included while requested");
			}
			if (null == message.signCertFile) {
				throw new ServletException(
						"sign cert not included while requested");
			}
			if (null == message.caCertFile) {
				throw new ServletException(
						"CA cert not included while requested");
			}
			if (null == message.rootCertFile) {
				throw new ServletException(
						"root cert not included while requested");
			}
			authnCert = getCertificate(message.authnCertFile);
			signCert = getCertificate(message.signCertFile);
			caCert = getCertificate(message.caCertFile);
			rootCert = getCertificate(message.rootCertFile);
		}

		IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
				.locateService();
		if (null != identityIntegrityService) {
			/*
			 * First check if all required identity data is available.
			 */
			if (null == message.identitySignatureFile) {
				throw new ServletException(
						"identity signature data not included while request");
			}
			LOG.debug("identity signature file size: "
					+ message.identitySignatureFile.length);
			if (includeAddress) {
				if (null == message.addressSignatureFile) {
					throw new ServletException(
							"address signature data not included while requested");
				}
				LOG.debug("address signature file size: "
						+ message.addressSignatureFile.length);
			}
			if (null == message.rrnCertFile) {
				throw new ServletException(
						"national registry certificate not included while requested");
			}
			LOG.debug("RRN certificate file size: "
					+ message.rrnCertFile.length);
			/*
			 * Run identity integrity checks.
			 */
			X509Certificate rrnCertificate = getCertificate(message.rrnCertFile);
			PublicKey rrnPublicKey = rrnCertificate.getPublicKey();
			verifySignature(message.identitySignatureFile, rrnPublicKey,
					request, message.idFile);
			if (false == this.skipNationalNumberCheck) {
				String authnUserId = (String) session
						.getAttribute(AuthenticationDataMessageHandler.AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE);
				if (null != authnUserId) {
					if (false == authnUserId.equals(identity.nationalNumber)) {
						throw new ServletException("national number mismatch");
					}
				}
			}
			if (includeAddress) {
				byte[] addressFile = trimRight(message.addressFile);
				verifySignature(message.addressSignatureFile, rrnPublicKey,
						request, addressFile, message.identitySignatureFile);
			}
			LOG.debug("checking national registration certificate: "
					+ rrnCertificate.getSubjectX500Principal());
			X509Certificate rootCertificate = getCertificate(message.rootCertFile);
			List<X509Certificate> rrnCertificateChain = new LinkedList<X509Certificate>();
			rrnCertificateChain.add(rrnCertificate);
			rrnCertificateChain.add(rootCertificate);
			try {
				identityIntegrityService
						.checkNationalRegistrationCertificate(rrnCertificateChain);
			} catch (ExpiredCertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
			} catch (RevokedCertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_REVOKED);
			} catch (TrustCertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE_NOT_TRUSTED);
			} catch (CertificateSecurityException e) {
				return new FinishedMessage(ErrorCode.CERTIFICATE);
			} catch (Exception e) {
				if ("javax.ejb.EJBException".equals(e.getClass().getName())) {
					Exception exception;
					try {
						Method getCausedByExceptionMethod = e.getClass()
								.getMethod("getCausedByException",
										new Class[] {});
						exception = (Exception) getCausedByExceptionMethod
								.invoke(e, new Object[] {});
					} catch (Exception e2) {
						LOG.debug("error: " + e.getMessage(), e);
						throw new SecurityException(
								"error retrieving the root cause: "
										+ e2.getMessage());
					}
					if (exception instanceof ExpiredCertificateSecurityException) {
						return new FinishedMessage(
								ErrorCode.CERTIFICATE_EXPIRED);
					}
					if (exception instanceof RevokedCertificateSecurityException) {
						return new FinishedMessage(
								ErrorCode.CERTIFICATE_REVOKED);
					}
					if (exception instanceof TrustCertificateSecurityException) {
						return new FinishedMessage(
								ErrorCode.CERTIFICATE_NOT_TRUSTED);
					}
					if (exception instanceof CertificateSecurityException) {
						return new FinishedMessage(ErrorCode.CERTIFICATE);
					}
				}
				throw new SecurityException(
						"error checking the NRN certificate: " + e.getMessage(),
						e);
			}
		}

		if (null != message.photoFile) {
			LOG.debug("photo file size: " + message.photoFile.length);
			if (false == includePhoto) {
				throw new ServletException("photo include while not requested");
			}
			/*
			 * Photo integrity check.
			 */
			byte[] expectedPhotoDigest = identity.photoDigest;
			byte[] actualPhotoDigest = digestPhoto(message.photoFile);
			if (false == Arrays.equals(expectedPhotoDigest, actualPhotoDigest)) {
				throw new ServletException("photo digest incorrect");
			}
		} else {
			if (true == includePhoto) {
				throw new ServletException("photo not included while requested");
			}
		}

		// push the identity into the session
		session.setAttribute(IDENTITY_SESSION_ATTRIBUTE, identity);
		if (null != address) {
			session.setAttribute(ADDRESS_SESSION_ATTRIBUTE, address);
		}
		if (null != message.photoFile) {
			session.setAttribute(PHOTO_SESSION_ATTRIBUTE, message.photoFile);
		}

		if (includeCertificates) {
			session.setAttribute(AUTHN_CERT_SESSION_ATTRIBUTE, authnCert);
			session.setAttribute(SIGN_CERT_SESSION_ATTRIBUTE, signCert);
			session.setAttribute(CA_CERT_SESSION_ATTRIBUTE, caCert);
			session.setAttribute(ROOT_CERT_SESSION_ATTRIBUTE, rootCert);
		}

		EIdData eidData = (EIdData) session.getAttribute(EID_SESSION_ATTRIBUTE);
		if (null == eidData) {
			eidData = new EIdData();
			session.setAttribute(EID_SESSION_ATTRIBUTE, eidData);
		}
		eidData.identity = identity;
		eidData.address = address;
		eidData.photo = message.photoFile;
		if (includeCertificates) {
			EIdCertsData eidCertsData = new EIdCertsData();
			session.setAttribute(EID_CERTS_SESSION_ATTRIBUTE, eidCertsData);
			eidData.certs = eidCertsData;

			eidCertsData.authn = authnCert;
			eidCertsData.sign = signCert;
			eidCertsData.ca = caCert;
			eidCertsData.root = rootCert;

			session.setAttribute(AUTHN_CERT_SESSION_ATTRIBUTE, authnCert);
			session.setAttribute(SIGN_CERT_SESSION_ATTRIBUTE, signCert);
			session.setAttribute(CA_CERT_SESSION_ATTRIBUTE, caCert);
			session.setAttribute(ROOT_CERT_SESSION_ATTRIBUTE, rootCert);
		}

		if (this.includeDataFiles) {
			session.setAttribute(EID_DATA_IDENTITY_SESSION_ATTRIBUTE,
					message.idFile);
			session.setAttribute(EID_DATA_ADDRESS_SESSION_ATTRIBUTE,
					message.addressFile);
		}

		AuditService auditService = this.auditServiceLocator.locateService();
		if (null != auditService) {
			String userId = identity.nationalNumber;
			auditService.identified(userId);
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

	/**
	 * Tries to parse the X509 certificate.
	 * 
	 * @param certFile
	 * @return the X509 certificate, or <code>null</code> in case of a DER
	 *         decoding error.
	 */
	private X509Certificate getCertificate(byte[] certFile) {
		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(certFile));
			return certificate;
		} catch (CertificateException e) {
			LOG.warn("certificate error: " + e.getMessage(), e);
			LOG.debug("certificate size: " + certFile.length);
			LOG.debug("certificate file content: "
					+ Hex.encodeHexString(certFile));
			/*
			 * Missing eID authentication and eID non-repudiation certificates
			 * could become possible for future eID cards. A missing certificate
			 * is represented as a block of 1300 null bytes.
			 */
			if (1300 == certFile.length) {
				boolean missingCertificate = true;
				for (int idx = 0; idx < certFile.length; idx++) {
					if (0 != certFile[idx]) {
						missingCertificate = false;
					}
				}
				if (missingCertificate) {
					LOG.debug("the certificate data indicates a missing certificate");
				}
			}
			return null;
		}
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

	public void init(ServletConfig config) throws ServletException {
		// empty
	}
}
