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
	public Integer authnCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "CaCertFileSize")
	public Integer caCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "RootCaCertFileSize")
	public Integer rootCertFileSize;

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
			byte[] signatureValue, List<X509Certificate> authnCertChain)
			throws IOException, CertificateEncodingException {
		this.saltValueSize = saltValue.length;
		this.signatureValueSize = signatureValue.length;
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
		this.body = baos.toByteArray();
		X509Certificate authnCert = authnCertChain.get(0);
		X509Certificate citCaCert = authnCertChain.get(1);
		X509Certificate rootCaCert = authnCertChain.get(2);
		this.authnCertFileSize = getCertificateSize(authnCert);
		this.caCertFileSize = getCertificateSize(citCaCert);
		this.rootCertFileSize = getCertificateSize(rootCaCert);
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

		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			Collection<? extends Certificate> certificates = certificateFactory
					.generateCertificates(new ByteArrayInputStream(copy(
							this.body, idx, this.body.length - idx)));
			this.certificateChain = new LinkedList<X509Certificate>();
			for (Certificate certificate : certificates) {
				this.certificateChain.add((X509Certificate) certificate);
			}
		} catch (CertificateException e) {
			throw new RuntimeException("cert parsing error: " + e.getMessage(),
					e);
		}
	}

	public byte[] saltValue;

	public byte[] sessionId;

	public byte[] signatureValue;

	public List<X509Certificate> certificateChain;
}
