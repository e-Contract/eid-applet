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
 * Insecure Client Message transfer object.
 * 
 * @author Frank Cornelis
 * 
 */
@StateTransition(ProtocolState.INSECURE)
public class InsecureClientMessage extends AbstractProtocolMessage {
	@HttpHeader(TYPE_HTTP_HEADER)
	@MessageDiscriminator
	public static final String TYPE = InsecureClientMessage.class
			.getSimpleName();

	public InsecureClientMessage() {
		this(false);
	}

	public InsecureClientMessage(boolean warnOnly) {
		this.warnOnly = warnOnly;
	}

	@HttpHeader(HTTP_HEADER_PREFIX + "WarnOnly")
	public boolean warnOnly;
}
