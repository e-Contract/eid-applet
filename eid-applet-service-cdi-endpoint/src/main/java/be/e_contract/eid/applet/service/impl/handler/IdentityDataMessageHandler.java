/*
 * eID Applet Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

package be.e_contract.eid.applet.service.impl.handler;

import java.io.ByteArrayInputStream;
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
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.enterprise.event.Event;
import javax.inject.Inject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.e_contract.eid.applet.service.impl.BeIDContextQualifier;
import be.e_contract.eid.applet.service.impl.Handles;
import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.IdentificationEvent;
import be.fedict.eid.applet.service.cdi.IdentityEvent;
import be.fedict.eid.applet.service.cdi.SecurityAuditEvent;
import be.fedict.eid.applet.service.cdi.SecurityAuditEvent.Incident;
import be.fedict.eid.applet.service.impl.UserIdentifierUtil;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;
import be.fedict.eid.applet.service.spi.CertificateSecurityException;
import be.fedict.eid.applet.service.spi.ExpiredCertificateSecurityException;
import be.fedict.eid.applet.service.spi.RevokedCertificateSecurityException;
import be.fedict.eid.applet.service.spi.TrustCertificateSecurityException;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.IdentityDataMessage;

@Handles(IdentityDataMessage.class)
public class IdentityDataMessageHandler implements MessageHandler<IdentityDataMessage> {

	private static final Log LOG = LogFactory.getLog(IdentityDataMessageHandler.class);

	@Inject
	private Event<IdentityEvent> identityEvent;

	@Inject
	private Event<IdentificationEvent> identificationEvent;

	@Inject
	private Event<SecurityAuditEvent> securityAuditEvent;

	@Override
	public Object handleMessage(IdentityDataMessage message, Map<String, String> httpHeaders,
			HttpServletRequest request, HttpSession session) throws ServletException {
		LOG.debug("handle identity");

		X509Certificate rrnCertificate = getCertificate(message.rrnCertFile);
		X509Certificate rootCertificate = getCertificate(message.rootCertFile);
		List<X509Certificate> rrnCertificateChain = new LinkedList<X509Certificate>();
		rrnCertificateChain.add(rrnCertificate);
		rrnCertificateChain.add(rootCertificate);

		IdentificationEvent identificationEvent = new IdentificationEvent(rrnCertificateChain);
		BeIDContextQualifier contextQualifier = new BeIDContextQualifier(request);
		try {
			this.identificationEvent.select(contextQualifier).fire(identificationEvent);
		} catch (ExpiredCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_EXPIRED);
		} catch (RevokedCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_REVOKED);
		} catch (TrustCertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE_NOT_TRUSTED);
		} catch (CertificateSecurityException e) {
			return new FinishedMessage(ErrorCode.CERTIFICATE);
		}
		if (false == identificationEvent.isValid()) {
			SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.TRUST, rrnCertificate);
			this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
			throw new SecurityException("invalid national registry certificate chain");
		}

		verifySignature(contextQualifier, rrnCertificate.getSigAlgName(), message.identitySignatureFile, rrnCertificate,
				request, message.idFile);

		Identity identity = TlvParser.parse(message.idFile, Identity.class);

		if (null != message.photoFile) {
			LOG.debug("photo file size: " + message.photoFile.length);
			/*
			 * Photo integrity check.
			 */
			byte[] expectedPhotoDigest = identity.photoDigest;
			byte[] actualPhotoDigest = digestPhoto(getDigestAlgo(expectedPhotoDigest.length), message.photoFile);
			if (false == Arrays.equals(expectedPhotoDigest, actualPhotoDigest)) {
				SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.DATA_INTEGRITY,
						message.photoFile);
				this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
				throw new ServletException("photo digest incorrect");
			}
		}

		Address address;
		if (null != message.addressFile) {
			byte[] addressFile = trimRight(message.addressFile);
			verifySignature(contextQualifier, rrnCertificate.getSigAlgName(), message.addressSignatureFile,
					rrnCertificate, request, addressFile, message.identitySignatureFile);
			address = TlvParser.parse(message.addressFile, Address.class);
		} else {
			address = null;
		}

		/*
		 * Check the validity of the identity data as good as possible.
		 */
		GregorianCalendar cardValidityDateEndGregorianCalendar = identity.getCardValidityDateEnd();
		if (null != cardValidityDateEndGregorianCalendar) {
			Date now = new Date();
			Date cardValidityDateEndDate = cardValidityDateEndGregorianCalendar.getTime();
			if (now.after(cardValidityDateEndDate)) {
				SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.DATA_INTEGRITY, message.idFile);
				this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
				throw new SecurityException("eID card has expired");
			}
		}
		
		X509Certificate authCert = null;
		if (null != message.authnCertFile) {
			authCert = getCertificate(message.authnCertFile);
			if (null != authCert) {
				String userId = UserIdentifierUtil.getUserId(authCert);
				if (!userId.equals(identity.getNationalNumber())) {
					throw new SecurityException("mismatch between identity data and auth cert");
				}
			}
		}

		this.identityEvent.select(contextQualifier).fire(new IdentityEvent(identity, address, message.photoFile, authCert));
		return new FinishedMessage();
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
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
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(certFile));
			return certificate;
		} catch (CertificateException e) {
			LOG.warn("certificate error: " + e.getMessage(), e);
			LOG.debug("certificate size: " + certFile.length);
			LOG.debug("certificate file content: " + Hex.encodeHexString(certFile));
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

	private void verifySignature(BeIDContextQualifier contextQualifier, String signAlgo, byte[] signatureData,
			X509Certificate certificate, HttpServletRequest request, byte[]... data) throws ServletException {
		Signature signature;
		try {
			signature = Signature.getInstance(signAlgo);
		} catch (NoSuchAlgorithmException e) {
			throw new ServletException("algo error: " + e.getMessage(), e);
		}
		PublicKey publicKey = certificate.getPublicKey();
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
				SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.DATA_INTEGRITY, certificate,
						signatureData);
				this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
				throw new ServletException("signature incorrect");
			}
		} catch (SignatureException e) {
			SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.DATA_INTEGRITY, certificate,
					signatureData);
			this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
			throw new ServletException("signature error: " + e.getMessage(), e);
		}
	}

	private byte[] digestPhoto(String digestAlgoName, byte[] photoFile) {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(digestAlgoName);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("digest error: " + e.getMessage(), e);
		}
		byte[] photoDigest = messageDigest.digest(photoFile);
		return photoDigest;
	}

	private String getDigestAlgo(final int hashSize) throws RuntimeException {
		switch (hashSize) {
		case 20:
			return "SHA-1";
		case 28:
			return "SHA-224";
		case 32:
			return "SHA-256";
		case 48:
			return "SHA-384";
		case 64:
			return "SHA-512";
		}
		throw new RuntimeException("Failed to find guess algorithm for hash size of " + hashSize + " bytes");
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
}
