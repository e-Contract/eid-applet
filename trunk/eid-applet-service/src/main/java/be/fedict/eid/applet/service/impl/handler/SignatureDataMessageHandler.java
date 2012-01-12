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

import java.lang.reflect.Method;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.util.Arrays;

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

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuditService> auditServiceLocator;

	public static final String DIGEST_VALUE_SESSION_ATTRIBUTE = SignatureDataMessageHandler.class
			.getName()
			+ ".digestValue";

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
		byte[] expectedDigestValue = SignatureDataMessageHandler
				.getDigestValue(session);
		byte[] signatureDigestValue;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, signingPublicKey);
			byte[] signatureDigestInfoValue = cipher.doFinal(signatureValue);
			ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
			DigestInfo signatureDigestInfo = new DigestInfo((ASN1Sequence) aIn
					.readObject());
			signatureDigestValue = signatureDigestInfo.getDigest();
		} catch (Exception e) {
			LOG.debug("signature verification error: " + e.getMessage());
			throw new ServletException("signature verification error: "
					+ e.getMessage(), e);
		}

		if (false == Arrays.areEqual(expectedDigestValue, signatureDigestValue)) {
			AuditService auditService = this.auditServiceLocator
					.locateService();
			if (null != auditService) {
				String remoteAddress = request.getRemoteAddr();
				auditService.signatureError(remoteAddress, signingCertificate);
			}
			throw new ServletException("signature incorrect");
		}
		// no need to also check the digest algo

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

	public static void setDigestValue(byte[] digestValue, HttpSession session) {
		session.setAttribute(DIGEST_VALUE_SESSION_ATTRIBUTE, digestValue);
	}
}
