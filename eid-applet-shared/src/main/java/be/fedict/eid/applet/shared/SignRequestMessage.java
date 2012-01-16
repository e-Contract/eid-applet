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

import be.fedict.eid.applet.shared.annotation.Description;
import be.fedict.eid.applet.shared.annotation.HttpBody;
import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.NotNull;
import be.fedict.eid.applet.shared.annotation.StateTransition;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Sign request message transfer object.
 * 
 * @author Frank Cornelis
 * 
 */
@StateTransition(ProtocolState.SIGN)
public class SignRequestMessage extends AbstractProtocolMessage {
	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = SignRequestMessage.class.getSimpleName();

	@HttpHeader(HTTP_HEADER_PREFIX + "DigestAlgo")
	@NotNull
	public String digestAlgo;

	@HttpHeader(HTTP_HEADER_PREFIX + "Description")
	public String description;

	@HttpHeader(HTTP_HEADER_PREFIX + "RemoveCard")
	public boolean removeCard;

	@HttpHeader(HTTP_HEADER_PREFIX + "Logoff")
	public boolean logoff;

	@HttpHeader(HTTP_HEADER_PREFIX + "RequireSecureReader")
	public boolean requireSecureReader;

	@HttpHeader(HTTP_HEADER_PREFIX + "NoPKCS11")
	public boolean noPkcs11;

	@HttpBody
	@NotNull
	@Description("The digest value to be signed using the non-repudiation certificate")
	public byte[] digestValue;

	public SignRequestMessage() {
		super();
	}

	public SignRequestMessage(byte[] digestValue, String digestAlgo,
			String description, boolean logoff, boolean removeCard,
			boolean requireSecureReader) {
		this.digestValue = digestValue;
		this.digestAlgo = digestAlgo;
		this.description = description;
		this.logoff = logoff;
		this.removeCard = removeCard;
		this.requireSecureReader = requireSecureReader;
		this.noPkcs11 = true;
	}
}
