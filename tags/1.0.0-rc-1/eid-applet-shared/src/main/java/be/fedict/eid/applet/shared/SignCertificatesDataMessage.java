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

	public SignCertificatesDataMessage(X509Certificate[] certificateChain)
			throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (X509Certificate certificate : certificateChain) {
			try {
				baos.write(certificate.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new RuntimeException("certificate encoding error: "
						+ e.getMessage(), e);
			}
		}
		this.body = baos.toByteArray();
	}

	public SignCertificatesDataMessage(List<X509Certificate> certificateChain)
			throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (X509Certificate certificate : certificateChain) {
			try {
				baos.write(certificate.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new RuntimeException("certificate encoding error: "
						+ e.getMessage(), e);
			}
		}
		this.body = baos.toByteArray();
	}

	@PostConstruct
	public void postConstruct() {
		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			Collection<? extends Certificate> certificates = certificateFactory
					.generateCertificates(new ByteArrayInputStream(this.body));
			this.certificateChain = new LinkedList<X509Certificate>();
			for (Certificate certificate : certificates) {
				X509Certificate x509Certificate = (X509Certificate) certificate;
				this.certificateChain.add(x509Certificate);
			}
		} catch (CertificateException e) {
			throw new RuntimeException("certificate decoding error: "
					+ e.getMessage(), e);
		}
	}

	public List<X509Certificate> certificateChain;
}
