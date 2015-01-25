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
import java.util.LinkedList;
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
 * Signature Certificates/Identity Data Transfer Object.
 * 
 * @author Frank Cornelis
 * 
 */
@ResponsesAllowed({ SignRequestMessage.class, FinishedMessage.class })
@ProtocolStateAllowed(ProtocolState.SIGN_CERTS)
public class SignCertificatesDataMessage extends AbstractProtocolMessage {

	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = SignCertificatesDataMessage.class
			.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "SignCertFileSize")
	@NotNull
	public Integer signCertFileSize;

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
	public byte[] body;

	/**
	 * Default constructor.
	 */
	public SignCertificatesDataMessage() {
		super();
	}

	/**
	 * Main Constructor.
	 * 
	 * @param signCertFile
	 * @param citizenCaCertFile
	 * @param rootCaCertFile
	 * @param identityFile
	 *            optional
	 * @param addressFile
	 *            optional
	 * @param photoFile
	 *            optional
	 * @param identitySignFile
	 *            optional
	 * @param addressSignFile
	 *            optional
	 * @param nrnCertFile
	 *            optional
	 * @throws IOException
	 */
	public SignCertificatesDataMessage(byte[] signCertFile,
			byte[] citizenCaCertFile, byte[] rootCaCertFile,
			byte[] identityFile, byte[] addressFile, byte[] photoFile,
			byte[] identitySignFile, byte[] addressSignFile, byte[] nrnCertFile)
			throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		baos.write(signCertFile);
		this.signCertFileSize = signCertFile.length;

		baos.write(citizenCaCertFile);
		this.caCertFileSize = citizenCaCertFile.length;

		baos.write(rootCaCertFile);
		this.rootCertFileSize = rootCaCertFile.length;

		if (null != identityFile) {
			baos.write(identityFile);
			this.identityFileSize = identityFile.length;
		}
		if (null != addressFile) {
			baos.write(addressFile);
			this.addressFileSize = addressFile.length;
		}
		if (null != photoFile) {
			baos.write(photoFile);
			this.photoFileSize = photoFile.length;
		}
		if (null != identitySignFile) {
			baos.write(identitySignFile);
			this.identitySignatureFileSize = identitySignFile.length;
		}
		if (null != addressSignFile) {
			baos.write(addressSignFile);
			this.addressSignatureFileSize = addressSignFile.length;
		}
		if (null != nrnCertFile) {
			baos.write(nrnCertFile);
			this.rrnCertFileSize = nrnCertFile.length;
		}

		this.body = baos.toByteArray();
	}

	public SignCertificatesDataMessage(X509Certificate[] signCertChain)
			throws IOException, CertificateEncodingException {
		this(signCertChain[0].getEncoded(), signCertChain[1].getEncoded(),
				signCertChain[2].getEncoded(), null, null, null, null, null,
				null);
	}

	private byte[] copy(byte[] source, int idx, int count) {
		byte[] result = new byte[count];
		System.arraycopy(source, idx, result, 0, count);
		return result;
	}

	@PostConstruct
	public void postConstruct() {
		int idx = 0;
		byte[] signCertFile = copy(this.body, idx, this.signCertFileSize);
		idx += this.signCertFileSize;
		X509Certificate signCert = getCertificate(signCertFile);

		byte[] citizenCaCertFile = copy(this.body, idx, this.caCertFileSize);
		idx += this.caCertFileSize;
		X509Certificate citizenCaCert = getCertificate(citizenCaCertFile);

		byte[] rootCaCertFile = copy(this.body, idx, this.rootCertFileSize);
		idx += this.rootCertFileSize;
		this.rootCertificate = getCertificate(rootCaCertFile);

		this.certificateChain = new LinkedList<X509Certificate>();
		this.certificateChain.add(signCert);
		this.certificateChain.add(citizenCaCert);
		this.certificateChain.add(this.rootCertificate);

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
			byte[] nrnCertData = copy(this.body, idx, this.rrnCertFileSize);
			idx += this.rrnCertFileSize;
			this.rrnCertificate = getCertificate(nrnCertData);
		}
	}

	public byte[] identityData;

	public byte[] addressData;

	public byte[] photoData;

	public byte[] identitySignatureData;

	public byte[] addressSignatureData;

	public X509Certificate rrnCertificate;

	public X509Certificate rootCertificate;

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

	public List<X509Certificate> certificateChain;
}
