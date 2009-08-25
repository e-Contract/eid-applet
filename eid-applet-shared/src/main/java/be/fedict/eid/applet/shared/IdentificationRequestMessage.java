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

import be.fedict.eid.applet.shared.annotation.HttpHeader;
import be.fedict.eid.applet.shared.annotation.MessageDiscriminator;
import be.fedict.eid.applet.shared.annotation.StateTransition;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Identification request message transfer object.
 * 
 * @author Frank Cornelis
 * 
 */
@StateTransition(ProtocolState.IDENTIFY)
public class IdentificationRequestMessage extends AbstractProtocolMessage {

	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = IdentificationRequestMessage.class
			.getSimpleName();

	/**
	 * Default constructor.
	 */
	public IdentificationRequestMessage() {
		super();
	}

	/**
	 * Main constructor.
	 * 
	 * @param includeAddress
	 * @param includePhoto
	 * @param includeIntegrityData
	 * @param includeCertificates
	 * @param removeCard
	 */
	public IdentificationRequestMessage(boolean includeAddress,
			boolean includePhoto, boolean includeIntegrityData,
			boolean includeCertificates, boolean removeCard) {
		this.includeAddress = includeAddress;
		this.includePhoto = includePhoto;
		this.includeIntegrityData = includeIntegrityData;
		this.includeCertificates = includeCertificates;
		this.removeCard = removeCard;
	}

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeAddress")
	public boolean includeAddress;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludePhoto")
	public boolean includePhoto;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeIntegrityData")
	public boolean includeIntegrityData;

	@HttpHeader(HTTP_HEADER_PREFIX + "RemoveCard")
	public boolean removeCard;

	@HttpHeader(HTTP_HEADER_PREFIX + "IncludeCertificates")
	public boolean includeCertificates;
}
