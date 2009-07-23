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

package be.fedict.eid.applet.io;

import be.fedict.eid.applet.View;
import be.fedict.eid.applet.shared.protocol.ProtocolContext;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Local memory protocol context implementation.
 * 
 * @author fcorneli
 * 
 */
public class LocalAppletProtocolContext implements ProtocolContext {

	private final View view;

	public LocalAppletProtocolContext(View view) {
		this.view = view;
	}

	private ProtocolState protocolState;

	public ProtocolState getProtocolState() {
		this.view.addDetailMessage("current protocol state: "
				+ this.protocolState);
		return this.protocolState;
	}

	public void removeProtocolState() {
		this.view.addDetailMessage("removing protocol state");
		this.protocolState = null;
	}

	public void setProtocolState(ProtocolState protocolState) {
		this.view.addDetailMessage("protocol state transition: "
				+ protocolState);
		this.protocolState = protocolState;
	}
}
