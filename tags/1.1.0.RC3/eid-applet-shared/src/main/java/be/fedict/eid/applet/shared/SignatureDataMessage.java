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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
 * Signature Data transfer object.
 * 
 * @author Frank Cornelis
 * 
 */
@ResponsesAllowed(FinishedMessage.class)
@ProtocolStateAllowed(ProtocolState.SIGN)
public class SignatureDataMessage extends AbstractProtocolMessage {
	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = SignatureDataMessage.class
			.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "SignatureValueSize")
	@NotNull
	public Integer signatureValueSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "SignCertFileSize")
	@NotNull
	public Integer signCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "CaCertFileSize")
	@NotNull
	public Integer caCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "RootCaCertFileSize")
	@NotNull
	public Integer rootCertFileSize;

	@HttpBody
	@NotNull
	@Description("Contains concatenation of signature value and sign cert chain.")
	public byte[] body;

	public SignatureDataMessage() {
		super();
	}

	public SignatureDataMessage(byte[] signatureValue,
			List<X509Certificate> signCertChain) throws IOException,
			CertificateEncodingException {
		this(signatureValue, signCertChain.get(0).getEncoded(), signCertChain
				.get(1).getEncoded(), signCertChain.get(2).getEncoded());
	}

	public SignatureDataMessage(byte[] signatureValue, byte[] signCertFile,
			byte[] citizenCaCertFile, byte[] rootCaCertFile)
			throws IOException, CertificateEncodingException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		this.signatureValueSize = signatureValue.length;
		baos.write(signatureValue);
		baos.write(signCertFile);
		baos.write(citizenCaCertFile);
		baos.write(rootCaCertFile);
		this.body = baos.toByteArray();

		this.signCertFileSize = signCertFile.length;
		this.caCertFileSize = citizenCaCertFile.length;
		this.rootCertFileSize = rootCaCertFile.length;
	}

	private byte[] copy(byte[] source, int idx, int count) {
		byte[] result = new byte[count];
		System.arraycopy(source, idx, result, 0, count);
		return result;
	}

	@PostConstruct
	public void postConstruct() {
		int idx = 0;
		this.signatureValue = copy(this.body, idx, this.signatureValueSize);
		idx += this.signatureValueSize;

		byte[] signCertFile = copy(this.body, idx, this.signCertFileSize);
		idx += this.signCertFileSize;
		X509Certificate signCert = getCertificate(signCertFile);

		byte[] citizenCaCertFile = copy(this.body, idx, this.caCertFileSize);
		idx += this.caCertFileSize;
		X509Certificate citizenCaCert = getCertificate(citizenCaCertFile);

		byte[] rootCaCertFile = copy(this.body, idx, this.rootCertFileSize);
		idx += this.rootCertFileSize;
		X509Certificate rootCaCert = getCertificate(rootCaCertFile);

		this.certificateChain = new LinkedList<X509Certificate>();
		this.certificateChain.add(signCert);
		this.certificateChain.add(citizenCaCert);
		this.certificateChain.add(rootCaCert);
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

	public byte[] signatureValue;

	public List<X509Certificate> certificateChain;
}
