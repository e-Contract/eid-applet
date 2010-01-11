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
 * Identity Data Transfer Object.
 * 
 * @author Frank Cornelis
 * 
 */
@ResponsesAllowed(SignRequestMessage.class)
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

	@HttpBody
	@NotNull
	@Description("The non-repudiation certificate chain.")
	public byte[] body;

	/**
	 * Default constructor.
	 */
	public SignCertificatesDataMessage() {
		super();
	}

	public SignCertificatesDataMessage(byte[] signCertFile,
			byte[] citizenCaCertFile, byte[] rootCaCertFile) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(signCertFile);
		baos.write(citizenCaCertFile);
		baos.write(rootCaCertFile);
		this.body = baos.toByteArray();

		this.signCertFileSize = signCertFile.length;
		this.caCertFileSize = citizenCaCertFile.length;
		this.rootCertFileSize = rootCaCertFile.length;
	}

	public SignCertificatesDataMessage(X509Certificate[] signCertChain)
			throws IOException, CertificateEncodingException {
		this(signCertChain[0].getEncoded(), signCertChain[1].getEncoded(),
				signCertChain[2].getEncoded());
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

	public List<X509Certificate> certificateChain;
}
