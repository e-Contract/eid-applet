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

import be.fedict.eid.applet.shared.annotation.HttpBody;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.NotNull;
import be.fedict.eid.applet.shared.annotation.StateTransition;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Authentication request message transfer object.
 * 
 * @author Frank Cornelis
 * 
 */
@StateTransition(ProtocolState.AUTHENTICATE)
public class AuthenticationRequestMessage extends AbstractProtocolMessage {
	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = AuthenticationRequestMessage.class
			.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "RemoveCard")
	public boolean removeCard;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeHostname")
	public boolean includeHostname;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeInetAddress")
	public boolean includeInetAddress;

	@HttpHeader(HTTP_HEADER_PREFIX + "Logoff")
	public boolean logoff;

	@HttpHeader(HTTP_HEADER_PREFIX + "PreLogoff")
	public boolean preLogoff;

	@HttpHeader(HTTP_HEADER_PREFIX + "SessionIdChannelBinding")
	public boolean sessionIdChannelBinding;

	@HttpHeader(HTTP_HEADER_PREFIX + "ServerCertificateChannelBinding")
	public boolean serverCertificateChannelBinding;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeIdentity")
	public boolean includeIdentity;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeCertificates")
	public boolean includeCertificates;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeAddress")
	public boolean includeAddress;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludePhoto")
	public boolean includePhoto;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeIntegrityData")
	public boolean includeIntegrityData;

	@HttpHeader(HTTP_HEADER_PREFIX + "RequireSecureReader")
	public boolean requireSecureReader;

	@HttpHeader(HTTP_HEADER_PREFIX + "NoPKCS11")
	public boolean noPkcs11;

	@HttpHeader(HTTP_HEADER_PREFIX + "TransactionMessage")
	public String transactionMessage;

	@HttpBody
	@NotNull
	public byte[] challenge;

	public AuthenticationRequestMessage() {
		super();
	}

	public AuthenticationRequestMessage(byte[] challenge,
			boolean includeHostname, boolean includeInetAddress,
			boolean logoff, boolean preLogoff, boolean removeCard,
			boolean sessionIdChannelBinding,
			boolean serverCertificateChannelBinding, boolean includeIdentity,
			boolean includeCertificates, boolean includeAddress,
			boolean includePhoto, boolean includeIntegrityData,
			boolean requireSecureReader, String transactionMessage) {
		this.challenge = challenge;
		this.includeHostname = includeHostname;
		this.includeInetAddress = includeInetAddress;
		this.logoff = logoff;
		this.preLogoff = preLogoff;
		this.removeCard = removeCard;
		this.sessionIdChannelBinding = sessionIdChannelBinding;
		this.serverCertificateChannelBinding = serverCertificateChannelBinding;
		this.includeIdentity = includeIdentity;
		this.includeCertificates = includeCertificates;
		this.includeAddress = includeAddress;
		this.includePhoto = includePhoto;
		this.includeIntegrityData = includeIntegrityData;
		this.requireSecureReader = requireSecureReader;
		this.noPkcs11 = true;
		this.transactionMessage = transactionMessage;
	}
}
