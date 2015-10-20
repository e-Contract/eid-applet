/*
 * eID Applet Project.
 * Copyright (C) 2015 e-Contract.be BVBA.
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

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
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

import be.e_contract.eid.applet.service.impl.BeIDContextQualifier;
import be.e_contract.eid.applet.service.impl.Handles;
import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.IdentificationEvent;
import be.fedict.eid.applet.service.cdi.IdentityEvent;
import be.fedict.eid.applet.service.cdi.SecurityAuditEvent;
import be.fedict.eid.applet.service.cdi.SecurityAuditEvent.Incident;
import be.fedict.eid.applet.service.cdi.SignatureDigestEvent;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;
import be.fedict.eid.applet.service.spi.AuthorizationException;
import be.fedict.eid.applet.service.spi.CertificateSecurityException;
import be.fedict.eid.applet.service.spi.ExpiredCertificateSecurityException;
import be.fedict.eid.applet.service.spi.RevokedCertificateSecurityException;
import be.fedict.eid.applet.service.spi.TrustCertificateSecurityException;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.SignCertificatesDataMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

@Handles(SignCertificatesDataMessage.class)
public class SignCertificatesDataMessageHandler implements MessageHandler<SignCertificatesDataMessage>, Serializable {

	private static final long serialVersionUID = 1L;

	@Inject
	private Event<IdentityEvent> identityEvent;

	@Inject
	private Event<IdentificationEvent> identificationEvent;

	@Inject
	private Event<SignatureDigestEvent> signatureDigestEvent;

	@Inject
	private SignatureState signatureState;

	@Inject
	private Event<SecurityAuditEvent> securityAuditEvent;

	@Override
	public Object handleMessage(SignCertificatesDataMessage message, Map<String, String> httpHeaders,
			HttpServletRequest request, HttpSession session) throws ServletException {
		BeIDContextQualifier contextQualifier = new BeIDContextQualifier(request);
		if (null != message.identityData) {
			List<X509Certificate> rrnCertificateChain = new LinkedList<X509Certificate>();
			rrnCertificateChain.add(message.rrnCertificate);
			rrnCertificateChain.add(message.rootCertificate);

			IdentificationEvent identificationEvent = new IdentificationEvent(rrnCertificateChain);
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
				SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.TRUST, message.rrnCertificate);
				this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
				throw new SecurityException("invalid national registry certificate chain");
			}

			verifySignature(contextQualifier, message.rrnCertificate.getSigAlgName(), message.identitySignatureData,
					message.rrnCertificate, request, message.identityData);

			Identity identity = TlvParser.parse(message.identityData, Identity.class);

			if (null != message.photoData) {
				/*
				 * Photo integrity check.
				 */
				byte[] expectedPhotoDigest = identity.photoDigest;
				byte[] actualPhotoDigest = digestPhoto(getDigestAlgo(expectedPhotoDigest.length), message.photoData);
				if (false == Arrays.equals(expectedPhotoDigest, actualPhotoDigest)) {
					SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.DATA_INTEGRITY,
							message.photoData);
					this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
					throw new ServletException("photo digest incorrect");
				}
			}

			Address address;
			if (null != message.addressData) {
				byte[] addressFile = trimRight(message.addressData);
				verifySignature(contextQualifier, message.rrnCertificate.getSigAlgName(), message.addressSignatureData,
						message.rrnCertificate, request, addressFile, message.identitySignatureData);
				address = TlvParser.parse(message.addressData, Address.class);
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
					SecurityAuditEvent securityAuditEvent = new SecurityAuditEvent(Incident.DATA_INTEGRITY,
							message.identityData);
					this.securityAuditEvent.select(contextQualifier).fire(securityAuditEvent);
					throw new SecurityException("eID card has expired");
				}
			}

			this.identityEvent.select(contextQualifier).fire(new IdentityEvent(identity, address, message.photoData, null));
		}

		SignatureDigestEvent signatureDigestEvent = new SignatureDigestEvent(message.certificateChain);
		try {
			this.signatureDigestEvent.select(contextQualifier).fire(signatureDigestEvent);
		} catch (AuthorizationException e) {
			return new FinishedMessage(ErrorCode.AUTHORIZATION);
		}
		String digestAlgo = signatureDigestEvent.getDigestAlgo();
		boolean logoff = signatureDigestEvent.isLogoff();
		boolean requireSecureReader = false;
		boolean removeCard = signatureDigestEvent.isRemoveCard();
		String description = signatureDigestEvent.getDescription();
		byte[] digestValue = signatureDigestEvent.getDigestValue();

		// required for later verification
		this.signatureState.setDigestValue(digestValue);
		this.signatureState.setDigestAlgo(digestAlgo);

		return new SignRequestMessage(digestValue, digestAlgo, description, logoff, removeCard, requireSecureReader);
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
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
