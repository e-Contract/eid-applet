/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.impl.UserIdentifierUtil;
import be.fedict.eid.applet.service.spi.AuditService;
import be.fedict.eid.applet.service.spi.CertificateSecurityException;
import be.fedict.eid.applet.service.spi.ExpiredCertificateSecurityException;
import be.fedict.eid.applet.service.spi.RevokedCertificateSecurityException;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.service.spi.TrustCertificateSecurityException;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.SignatureDataMessage;

/**
 * Signature data message protocol handler.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(SignatureDataMessage.class)
public class SignatureDataMessageHandler implements
		MessageHandler<SignatureDataMessage> {

	private static final Log LOG = LogFactory
			.getLog(SignatureDataMessageHandler.class);

	public static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
			0x00, 0x04, 0x14 };

	public static final byte[] SHA224_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c };

	public static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

	public static final byte[] SHA384_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };

	public static final byte[] SHA512_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
			0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

	public static final byte[] RIPEMD160_DIGEST_INFO_PREFIX = new byte[] {
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01,
			0x05, 0x00, 0x04, 0x14 };

	public static final byte[] RIPEMD128_DIGEST_INFO_PREFIX = new byte[] {
			0x30, 0x1d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x02,
			0x05, 0x00, 0x04, 0x10 };

	public static final byte[] RIPEMD256_DIGEST_INFO_PREFIX = new byte[] {
			0x30, 0x2d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x03,
			0x05, 0x00, 0x04, 0x20 };

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuditService> auditServiceLocator;

	public static final String DIGEST_VALUE_SESSION_ATTRIBUTE = SignatureDataMessageHandler.class
			.getName() + ".digestValue";

	public static final String DIGEST_ALGO_SESSION_ATTRIBUTE = SignatureDataMessageHandler.class
			.getName() + ".digestAlgo";

	public Object handleMessage(SignatureDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("signature data message received");

		byte[] signatureValue = message.signatureValue;
		List<X509Certificate> certificateChain = message.certificateChain;
		if (certificateChain.isEmpty()) {
			throw new ServletException("certificate chain is empty");
		}
		X509Certificate signingCertificate = certificateChain.get(0);
		if (null == signingCertificate) {
			throw new ServletException("non-repudiation certificate missing");
		}
		LOG.debug("non-repudiation signing certificate: "
				+ signingCertificate.getSubjectX500Principal());
		PublicKey signingPublicKey = signingCertificate.getPublicKey();

		/*
		 * Verify the signature.
		 */
		String digestAlgo = SignatureDataMessageHandler.getDigestAlgo(session);
		byte[] expectedDigestValue = SignatureDataMessageHandler
				.getDigestValue(session);
		if (digestAlgo.endsWith("-PSS")) {
			LOG.debug("verifying RSA/PSS signature");
			try {
				Signature signature = Signature.getInstance("RAWRSASSA-PSS",
						BouncyCastleProvider.PROVIDER_NAME);
				if ("SHA-256-PSS".equals(digestAlgo)) {
					LOG.debug("RSA/PSS SHA256");
					signature.setParameter(new PSSParameterSpec("SHA-256",
							"MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
				}
				signature.initVerify(signingPublicKey);
				signature.update(expectedDigestValue);
				boolean result = signature.verify(signatureValue);
				if (false == result) {
					throw new SecurityException("signature incorrect");
				}
			} catch (Exception e) {
				LOG.debug("signature verification error: " + e.getMessage(), e);
				throw new ServletException("signature verification error: "
						+ e.getMessage(), e);
			}
		} else {
			try {
				Signature signature = Signature.getInstance("RawRSA",
						BouncyCastleProvider.PROVIDER_NAME);
				signature.initVerify(signingPublicKey);
				ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
				if ("SHA-1".equals(digestAlgo) || "SHA1".equals(digestAlgo)) {
					digestInfo.write(SHA1_DIGEST_INFO_PREFIX);
				} else if ("SHA-224".equals(digestAlgo)) {
					digestInfo.write(SHA224_DIGEST_INFO_PREFIX);
				} else if ("SHA-256".equals(digestAlgo)) {
					digestInfo.write(SHA256_DIGEST_INFO_PREFIX);
				} else if ("SHA-384".equals(digestAlgo)) {
					digestInfo.write(SHA384_DIGEST_INFO_PREFIX);
				} else if ("SHA-512".equals(digestAlgo)) {
					digestInfo.write(SHA512_DIGEST_INFO_PREFIX);
				} else if ("RIPEMD160".equals(digestAlgo)) {
					digestInfo.write(RIPEMD160_DIGEST_INFO_PREFIX);
				} else if ("RIPEMD128".equals(digestAlgo)) {
					digestInfo.write(RIPEMD128_DIGEST_INFO_PREFIX);
				} else if ("RIPEMD256".equals(digestAlgo)) {
					digestInfo.write(RIPEMD256_DIGEST_INFO_PREFIX);
				}
				digestInfo.write(expectedDigestValue);
				signature.update(digestInfo.toByteArray());
				boolean result = signature.verify(signatureValue);
				if (false == result) {
					AuditService auditService = this.auditServiceLocator
							.locateService();
					if (null != auditService) {
						String remoteAddress = request.getRemoteAddr();
						auditService.signatureError(remoteAddress,
								signingCertificate);
					}
					throw new SecurityException("signature incorrect");
				}
			} catch (Exception e) {
				LOG.debug("signature verification error: " + e.getMessage());
				throw new ServletException("signature verification error: "
						+ e.getMessage(), e);
			}
		}

		AuditService auditService = this.auditServiceLocator.locateService();
		if (null != auditService) {
			String userId = UserIdentifierUtil.getUserId(signingCertificate);
			auditService.signed(userId);
		}

		SignatureService signatureService = this.signatureServiceLocator
				.locateService();
		try {
			signatureService.postSign(signatureValue, certificateChain);
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
			throw new SecurityException("signature service error: "
					+ e.getMessage(), e);
		}

		return new FinishedMessage();
	}

	public void init(ServletConfig config) throws ServletException {
		// empty
	}

	public static byte[] getDigestValue(HttpSession session) {
		return (byte[]) session.getAttribute(DIGEST_VALUE_SESSION_ATTRIBUTE);
	}

	public static void setDigestValue(byte[] digestValue, String digestAlgo,
			HttpSession session) {
		session.setAttribute(DIGEST_VALUE_SESSION_ATTRIBUTE, digestValue);
		session.setAttribute(DIGEST_ALGO_SESSION_ATTRIBUTE, digestAlgo);
	}

	public static String getDigestAlgo(HttpSession session) {
		String digestAlgo = (String) session
				.getAttribute(DIGEST_ALGO_SESSION_ATTRIBUTE);
		return digestAlgo;
	}
}
