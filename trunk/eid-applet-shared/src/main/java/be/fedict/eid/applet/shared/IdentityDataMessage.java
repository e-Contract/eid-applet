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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import be.fedict.eid.applet.shared.annotation.Description;
import be.fedict.eid.applet.shared.annotation.HttpBody;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.NotNull;
import be.fedict.eid.applet.shared.annotation.PostConstruct;
import be.fedict.eid.applet.shared.annotation.ProtocolStateAllowed;
import be.fedict.eid.applet.shared.annotation.ResponsesAllowed;
import be.fedict.eid.applet.shared.annotation.ValidateSemanticalIntegrity;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Identity Data Transfer Object.
 * 
 * @author Frank Cornelis
 * 
 */
@ValidateSemanticalIntegrity(IdentityDataMessageSemanticValidator.class)
@ResponsesAllowed(FinishedMessage.class)
@ProtocolStateAllowed(ProtocolState.IDENTIFY)
public class IdentityDataMessage extends AbstractProtocolMessage {

	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = IdentityDataMessage.class.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "IdentityFileSize")
	@NotNull
	public Integer identityFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AddressFileSize")
	public Integer addressFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "PhotoFileSize")
	public Integer photoFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "IdentitySignatureFileSize")
	public Integer identitySignatureFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AddressSignatureFileSize")
	public Integer addressSignatureFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "RrnCertFileSize")
	public Integer rrnCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "RootCertFileSize")
	public Integer rootCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "AuthnCertFileSize")
	public Integer authnCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "SignCertFileSize")
	public Integer signCertFileSize;

	@HttpHeader(HTTP_HEADER_PREFIX + "CaCertFileSize")
	public Integer caCertFileSize;

	@HttpBody
	@NotNull
	@Description("Concatenation of identity file, optional address file, optional photo file, optional identity signature file, optional address signature file, and optional national registry certificate and root certificate.")
	// TODO: @MaxSize(1024 * 100)
	public byte[] body;

	/**
	 * Default constructor.
	 */
	public IdentityDataMessage() {
		super();
	}

	/**
	 * Main constructor.
	 * 
	 * @param idFile
	 * @param addressFile
	 * @param photoFile
	 * @param identitySignatureFile
	 * @param addressSignatureFile
	 * @param rrnCertFile
	 * @param rootCertFile
	 * @param authnCertFile
	 * @param signCertFile
	 * @param caCertFile
	 * @throws IOException
	 */
	public IdentityDataMessage(byte[] idFile, byte[] addressFile,
			byte[] photoFile, byte[] identitySignatureFile,
			byte[] addressSignatureFile, byte[] rrnCertFile,
			byte[] rootCertFile, byte[] authnCertFile, byte[] signCertFile,
			byte[] caCertFile) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		this.identityFileSize = idFile.length;
		baos.write(idFile);
		if (null != addressFile) {
			baos.write(addressFile);
			this.addressFileSize = addressFile.length;
		}
		if (null != photoFile) {
			baos.write(photoFile);
			this.photoFileSize = photoFile.length;
		}
		if (null != identitySignatureFile) {
			baos.write(identitySignatureFile);
			this.identitySignatureFileSize = identitySignatureFile.length;
		}
		if (null != addressSignatureFile) {
			baos.write(addressSignatureFile);
			this.addressSignatureFileSize = addressSignatureFile.length;
		}
		if (null != authnCertFile) {
			baos.write(authnCertFile);
			this.authnCertFileSize = authnCertFile.length;
		}
		if (null != signCertFile) {
			baos.write(signCertFile);
			this.signCertFileSize = signCertFile.length;
		}
		if (null != caCertFile) {
			baos.write(caCertFile);
			this.caCertFileSize = caCertFile.length;
		}
		if (null != rrnCertFile) {
			baos.write(rrnCertFile);
			this.rrnCertFileSize = rrnCertFile.length;
		}
		if (null != rootCertFile) {
			baos.write(rootCertFile);
			this.rootCertFileSize = rootCertFile.length;
		}
		this.body = baos.toByteArray();
	}

	@PostConstruct
	public void postConstruct() {
		int idx = 0;
		this.idFile = Arrays.copyOfRange(this.body, 0, this.identityFileSize);
		idx += this.identityFileSize;

		if (null != this.addressFileSize) {
			this.addressFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.addressFileSize);
			idx += this.addressFileSize;
		}

		if (null != this.photoFileSize) {
			this.photoFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.photoFileSize);
			idx += this.photoFileSize;
		}

		if (null != this.identitySignatureFileSize) {
			this.identitySignatureFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.identitySignatureFileSize);
			idx += this.identitySignatureFileSize;
		}

		if (null != this.addressSignatureFileSize) {
			this.addressSignatureFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.addressSignatureFileSize);
			idx += this.addressSignatureFileSize;
		}

		if (null != this.authnCertFileSize) {
			this.authnCertFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.authnCertFileSize);
			idx += this.authnCertFileSize;
		}

		if (null != this.signCertFileSize) {
			this.signCertFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.signCertFileSize);
			idx += this.signCertFileSize;
		}

		if (null != this.caCertFileSize) {
			this.caCertFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.caCertFileSize);
			idx += this.caCertFileSize;
		}

		if (null != this.rrnCertFileSize) {
			this.rrnCertFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.rrnCertFileSize);
			idx += this.rrnCertFileSize;
		}

		if (null != this.rootCertFileSize) {
			this.rootCertFile = Arrays.copyOfRange(this.body, idx, idx
					+ this.rootCertFileSize);
			idx += this.rootCertFileSize;
		}
	}

	public byte[] idFile;

	public byte[] addressFile;

	public byte[] photoFile;

	public byte[] identitySignatureFile;

	public byte[] addressSignatureFile;

	public byte[] rrnCertFile;

	public byte[] rootCertFile;

	public byte[] authnCertFile;

	public byte[] signCertFile;

	public byte[] caCertFile;
}
