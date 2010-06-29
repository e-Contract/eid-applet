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

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.dto.DTOMapper;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;
import be.fedict.eid.applet.service.spi.AddressDTO;
import be.fedict.eid.applet.service.spi.AuditService;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityDTO;
import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.service.spi.SignatureServiceEx;
import be.fedict.eid.applet.shared.SignCertificatesDataMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

/**
 * Sign Certificate Data Message Handler.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(SignCertificatesDataMessage.class)
public class SignCertificatesDataMessageHandler implements
		MessageHandler<SignCertificatesDataMessage> {

	private static final Log LOG = LogFactory
			.getLog(SignCertificatesDataMessageHandler.class);

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME)
	private boolean removeCard;

	@InitParam(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME)
	private boolean logoff;

	@InitParam(HelloMessageHandler.REQUIRE_SECURE_READER_INIT_PARAM_NAME)
	private boolean requireSecureReader;

	@InitParam(HelloMessageHandler.NO_PKCS11_INIT_PARAM_NAME)
	private boolean noPkcs11;

	@InitParam(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)
	private boolean includePhoto;

	@InitParam(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)
	private boolean includeAddress;

	@InitParam(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)
	private boolean includeIdentity;

	@InitParam(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuditService> auditServiceLocator;

	public Object handleMessage(SignCertificatesDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		SignatureService signatureService = this.signatureServiceLocator
				.locateService();

		List<X509Certificate> signingCertificateChain = message.certificateChain;
		X509Certificate signingCertificate = signingCertificateChain.get(0);
		if (null == signingCertificate) {
			throw new ServletException("missing non-repudiation certificate");
		}
		LOG.debug("signing certificate: "
				+ signingCertificateChain.get(0).getSubjectX500Principal());

		Identity identity = null;
		Address address = null;
		byte[] photo = null;
		if (this.includeIdentity || this.includeAddress || this.includePhoto) {
			/*
			 * Pre-sign phase including identity data.
			 */
			if (this.includeIdentity) {
				if (null == message.identityData) {
					throw new ServletException("identity data missing");
				}
				identity = TlvParser
						.parse(message.identityData, Identity.class);
			}

			if (this.includeAddress) {
				if (null == message.addressData) {
					throw new ServletException("address data missing");
				}
				address = TlvParser.parse(message.addressData, Address.class);
			}

			if (this.includePhoto) {
				if (null == message.photoData) {
					throw new ServletException("photo data missing");
				}
				if (null != identity) {
					byte[] expectedPhotoDigest = identity.photoDigest;
					byte[] actualPhotoDigest = digestPhoto(message.photoData);
					if (false == Arrays.equals(expectedPhotoDigest,
							actualPhotoDigest)) {
						throw new ServletException("photo digest incorrect");
					}
				}
				photo = message.photoData;
			}

			IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
					.locateService();
			if (null != identityIntegrityService) {
				if (null == message.rrnCertificate) {
					throw new ServletException(
							"national registry certificate not included while requested");
				}
				PublicKey rrnPublicKey = message.rrnCertificate.getPublicKey();
				if (null != message.identityData) {
					if (null == message.identitySignatureData) {
						throw new ServletException(
								"missing identity data signature");
					}
					verifySignature(message.identitySignatureData,
							rrnPublicKey, request, message.identityData);
					if (null != message.addressData) {
						if (null == message.addressSignatureData) {
							throw new ServletException(
									"missing address data signature");
						}
						byte[] addressFile = trimRight(message.addressData);
						verifySignature(message.addressSignatureData,
								rrnPublicKey, request, addressFile,
								message.identitySignatureData);
					}
				}
			}
		}

		DigestInfo digestInfo;
		LOG.debug("signature service class: "
				+ signatureService.getClass().getName());
		if (SignatureServiceEx.class.isAssignableFrom(signatureService
				.getClass())) {
			LOG.debug("SignatureServiceEx SPI implementation detected");
			/*
			 * The SignatureServiceEx SPI can also receive the identity during
			 * the pre-sign phase.
			 */
			SignatureServiceEx signatureServiceEx = (SignatureServiceEx) signatureService;
			DTOMapper dtoMapper = new DTOMapper();
			IdentityDTO identityDTO = dtoMapper
					.map(identity, IdentityDTO.class);
			AddressDTO addressDTO = dtoMapper.map(address, AddressDTO.class);
			try {
				digestInfo = signatureServiceEx.preSign(null,
						signingCertificateChain, identityDTO, addressDTO,
						message.photoData);
			} catch (NoSuchAlgorithmException e) {
				throw new ServletException("no such algo: " + e.getMessage(), e);
			}
		} else {
			LOG.debug("regular SignatureService SPI implementation");
			try {
				digestInfo = signatureService.preSign(null,
						signingCertificateChain);
			} catch (NoSuchAlgorithmException e) {
				throw new ServletException("no such algo: " + e.getMessage(), e);
			}
		}

		// also save it in the session for later verification
		SignatureDataMessageHandler.setDigestValue(digestInfo.digestValue,
				session);

		SignRequestMessage signRequestMessage = new SignRequestMessage(
				digestInfo.digestValue, digestInfo.digestAlgo,
				digestInfo.description, this.logoff, this.removeCard,
				this.requireSecureReader, this.noPkcs11);
		return signRequestMessage;
	}

	public void init(ServletConfig config) throws ServletException {
		// empty
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
