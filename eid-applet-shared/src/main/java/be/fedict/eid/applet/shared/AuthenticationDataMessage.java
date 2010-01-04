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

package be.fedict.eid.applet.shared;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import be.fedict.eid.applet.shared.annotation.Description;
import be.fedict.eid.applet.shared.annotation.HttpBody;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.NotNull;
import be.fedict.eid.applet.shared.annotation.PostConstruct;
import be.fedict.eid.applet.shared.annotation.ProtocolStateAllowed;
import be.fedict.eid.applet.shared.annotation.ResponsesAllowed;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Authentication Data transfer object.
 * 
 * @author Frank Cornelis
 * 
 */
@ResponsesAllowed(FinishedMessage.class)
@ProtocolStateAllowed(ProtocolState.AUTHENTICATE)
public class AuthenticationDataMessage extends AbstractProtocolMessage {
	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = AuthenticationDataMessage.class
			.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "SignatureValueSize")
	@NotNull
	public Integer signatureValueSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "SaltValueSize")
	@NotNull
	public Integer saltValueSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "SessionIdSize")
	public Integer sessionIdSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AuthnCertFileSize")
	@NotNull
	public Integer authnCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "CaCertFileSize")
	@NotNull
	public Integer caCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "RootCaCertFileSize")
	@NotNull
	public Integer rootCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "IdentityFileSize")
	public Integer identityFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AddressFileSize")
	public Integer addressFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "PhotoFileSize")
	public Integer photoFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "IdentitySignatureFileSize")
	public Integer identitySignatureFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AddressSignatureFileSize")
	public Integer addressSignatureFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "NationalRegistryCertFileSize")
	public Integer rrnCertFileSize;

	@HttpBody
	@NotNull
	@Description("Contains concatenation of salt value, optional session id, signature value, and authn cert chain.")
	public byte[] body;

	/**
	 * Default constructor.
	 */
	public AuthenticationDataMessage() {
		super();
	}

	/**
	 * Main constructor.
	 * 
	 * @param saltValue
	 * @param sessionId
	 *            the optional TLS session identifier.
	 * @param signatureValue
	 * @param authnCertChain
	 * @throws IOException
	 * @throws CertificateEncodingException
	 */
	public AuthenticationDataMessage(byte[] saltValue, byte[] sessionId,
			byte[] signatureValue, List<X509Certificate> authnCertChain,
			byte[] identityData, byte[] addressData, byte[] photoData,
			byte[] identitySignatureData, byte[] addressSignatureData,
			byte[] rrnCertData) throws IOException,
			CertificateEncodingException {
		this.saltValueSize = saltValue.length;
		this.signatureValueSize = signatureValue.length;
		X509Certificate authnCert = authnCertChain.get(0);
		this.authnCertFileSize = getCertificateSize(authnCert);
		X509Certificate citCaCert = authnCertChain.get(1);
		this.caCertFileSize = getCertificateSize(citCaCert);
		X509Certificate rootCaCert = authnCertChain.get(2);
		this.rootCertFileSize = getCertificateSize(rootCaCert);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(saltValue);
		if (null != sessionId) {
			this.sessionIdSize = sessionId.length;
			baos.write(sessionId);
		}
		baos.write(signatureValue);
		for (X509Certificate cert : authnCertChain) {
			baos.write(cert.getEncoded());
		}
		if (null != identityData) {
			baos.write(identityData);
			this.identityFileSize = identityData.length;
		}
		if (null != addressData) {
			baos.write(addressData);
			this.addressFileSize = addressData.length;
		}
		if (null != photoData) {
			baos.write(photoData);
			this.photoFileSize = photoData.length;
		}
		if (null != identitySignatureData) {
			baos.write(identitySignatureData);
			this.identitySignatureFileSize = identitySignatureData.length;
		}
		if (null != addressSignatureData) {
			baos.write(addressSignatureData);
			this.addressSignatureFileSize = addressSignatureData.length;
		}
		if (null != rrnCertData) {
			baos.write(rrnCertData);
			this.rrnCertFileSize = rrnCertData.length;
		}
		this.body = baos.toByteArray();
	}

	private int getCertificateSize(X509Certificate certificate) {
		try {
			return certificate.getEncoded().length;
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("certificate encoding error: "
					+ e.getMessage(), e);
		}
	}

	private byte[] copy(byte[] source, int idx, int count) {
		byte[] result = new byte[count];
		System.arraycopy(source, idx, result, 0, count);
		return result;
	}

	@PostConstruct
	public void postConstruct() {
		int idx = 0;
		if (0 == this.saltValueSize) {
			throw new RuntimeException("salt bytes required");
		}
		this.saltValue = copy(this.body, idx, this.saltValueSize);
		idx += this.saltValueSize;

		if (null != this.sessionIdSize) {
			this.sessionId = copy(this.body, idx, this.sessionIdSize);
			idx += this.sessionIdSize;
		}

		if (this.signatureValueSize != 128) {
			throw new RuntimeException("signature value size invalid");
		}
		this.signatureValue = copy(this.body, idx, this.signatureValueSize);
		idx += this.signatureValueSize;

		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException("cert factory error: " + e.getMessage(),
					e);
		}
		try {
			int certsSize = this.authnCertFileSize + this.caCertFileSize
					+ this.rootCertFileSize;
			Collection<? extends Certificate> certificates = certificateFactory
					.generateCertificates(new ByteArrayInputStream(copy(
							this.body, idx, certsSize)));
			this.certificateChain = new LinkedList<X509Certificate>();
			for (Certificate certificate : certificates) {
				this.certificateChain.add((X509Certificate) certificate);
			}
			idx += certsSize;
		} catch (CertificateException e) {
			throw new RuntimeException("cert parsing error: " + e.getMessage(),
					e);
		}

		if (null != this.identityFileSize) {
			this.identityData = copy(this.body, idx, this.identityFileSize);
			idx += this.identityFileSize;
		}

		if (null != this.addressFileSize) {
			this.addressData = copy(this.body, idx, this.addressFileSize);
			idx += this.addressFileSize;
		}

		if (null != this.photoFileSize) {
			this.photoData = copy(this.body, idx, this.photoFileSize);
			idx += this.photoFileSize;
		}

		if (null != this.identitySignatureFileSize) {
			this.identitySignatureData = copy(this.body, idx,
					this.identitySignatureFileSize);
			idx += this.identitySignatureFileSize;
		}

		if (null != this.addressSignatureFileSize) {
			this.addressSignatureData = copy(this.body, idx,
					this.addressSignatureFileSize);
			idx += this.addressSignatureFileSize;
		}

		if (null != this.rrnCertFileSize) {
			byte[] rrnCertData = copy(this.body, idx, this.rrnCertFileSize);
			try {
				this.rrnCertificate = (X509Certificate) certificateFactory
						.generateCertificate(new ByteArrayInputStream(
								rrnCertData));
			} catch (CertificateException e) {
				throw new RuntimeException("cert parsing error: "
						+ e.getMessage(), e);
			}
			idx += this.rrnCertFileSize;
		}
	}

	public byte[] saltValue;

	public byte[] sessionId;

	public byte[] signatureValue;

	public List<X509Certificate> certificateChain;

	public byte[] identityData;

	public byte[] addressData;

	public byte[] photoData;

	public byte[] identitySignatureData;

	public byte[] addressSignatureData;

	public X509Certificate rrnCertificate;
}
