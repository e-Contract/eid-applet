/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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

package be.fedict.eid.applet.shared;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

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
@ResponsesAllowed({ FinishedMessage.class, AuthSignRequestMessage.class })
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

	@HttpHeader(HTTP_HEADER_PREFIX + "SignCertFileSize")
	public Integer signCertFileSize;

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

	@HttpHeader(HTTP_HEADER_PREFIX + "ServerCertFileSize")
	public Integer serverCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "TransactionMessageSignatureSize")
	public Integer transactionMessageSignatureSize;

	@HttpBody
	@NotNull
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
	 * @param serverCertData
	 *            the applet also needs to communicate the server SSL
	 *            certificate in case of channel binding as the server not
	 *            always knows its own identity.
	 * @param transactionMessageSignature
	 *            the optional signed transaction message.
	 * @throws IOException
	 * @throws CertificateEncodingException
	 */
	public AuthenticationDataMessage(byte[] saltValue, byte[] sessionId,
			byte[] signatureValue, byte[] authnCertFile, byte[] citCaCertFile,
			byte[] rootCaCertFile, byte[] signCertFile, byte[] identityData,
			byte[] addressData, byte[] photoData, byte[] identitySignatureData,
			byte[] addressSignatureData, byte[] rrnCertData,
			byte[] serverCertData, byte[] transactionMessageSignature)
			throws IOException, CertificateEncodingException {
		this.saltValueSize = saltValue.length;
		this.signatureValueSize = signatureValue.length;
		this.authnCertFileSize = authnCertFile.length;
		this.caCertFileSize = citCaCertFile.length;
		this.rootCertFileSize = rootCaCertFile.length;

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(saltValue);
		if (null != sessionId) {
			this.sessionIdSize = sessionId.length;
			baos.write(sessionId);
		}
		baos.write(signatureValue);

		baos.write(authnCertFile);
		baos.write(citCaCertFile);
		baos.write(rootCaCertFile);

		if (null != signCertFile) {
			this.signCertFileSize = signCertFile.length;
			baos.write(signCertFile);
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
		if (null != serverCertData) {
			baos.write(serverCertData);
			this.serverCertFileSize = serverCertData.length;
		}
		if (null != transactionMessageSignature) {
			baos.write(transactionMessageSignature);
			this.transactionMessageSignatureSize = transactionMessageSignature.length;
		}
		this.body = baos.toByteArray();
	}

	public AuthenticationDataMessage(byte[] saltValue, byte[] sessionId,
			byte[] signatureValue, List<X509Certificate> authnCertChain,
			byte[] signCertFile, byte[] identityData, byte[] addressData,
			byte[] photoData, byte[] identitySignatureData,
			byte[] addressSignatureData, byte[] rrnCertData,
			byte[] serverCertData, byte[] transactionMessageSignature)
			throws IOException, CertificateEncodingException {
		this(saltValue, sessionId, signatureValue, authnCertChain.get(0)
				.getEncoded(), authnCertChain.get(1).getEncoded(),
				authnCertChain.get(2).getEncoded(), signCertFile, identityData,
				addressData, photoData, identitySignatureData,
				addressSignatureData, rrnCertData, serverCertData,
				transactionMessageSignature);
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

		this.signatureValue = copy(this.body, idx, this.signatureValueSize);
		idx += this.signatureValueSize;

		byte[] authnCertFile = copy(this.body, idx, this.authnCertFileSize);
		idx += this.authnCertFileSize;
		this.authnCert = getCertificate(authnCertFile);

		byte[] citizenCaCertFile = copy(this.body, idx, this.caCertFileSize);
		idx += this.caCertFileSize;
		this.citizenCaCert = getCertificate(citizenCaCertFile);

		byte[] rootCaCertFile = copy(this.body, idx, this.rootCertFileSize);
		idx += this.rootCertFileSize;
		this.rootCaCert = getCertificate(rootCaCertFile);

		if (null != this.signCertFileSize) {
			byte[] signCertFile = copy(this.body, idx, this.signCertFileSize);
			idx += this.signCertFileSize;
			this.signCert = getCertificate(signCertFile);
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
			this.rrnCertificate = getCertificate(rrnCertData);
			idx += this.rrnCertFileSize;
		}

		if (null != this.serverCertFileSize) {
			byte[] serverCertData = copy(this.body, idx,
					this.serverCertFileSize);
			this.serverCertificate = getCertificate(serverCertData);
			idx += this.serverCertFileSize;
		}

		if (null != this.transactionMessageSignatureSize) {
			this.transactionMessageSignature = copy(this.body, idx,
					this.transactionMessageSignatureSize);
			idx += this.transactionMessageSignatureSize;
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
			/*
			 * Can happen in case of missing certificates. Missing certificates
			 * are represented by means of 1300 null bytes.
			 */
			return null;
		}
	}

	public byte[] saltValue;

	public byte[] sessionId;

	public byte[] signatureValue;

	public X509Certificate authnCert;

	public X509Certificate citizenCaCert;

	public X509Certificate rootCaCert;

	public X509Certificate signCert;

	public byte[] identityData;

	public byte[] addressData;

	public byte[] photoData;

	public byte[] identitySignatureData;

	public byte[] addressSignatureData;

	public X509Certificate rrnCertificate;

	public X509Certificate serverCertificate;

	public byte[] transactionMessageSignature;
}