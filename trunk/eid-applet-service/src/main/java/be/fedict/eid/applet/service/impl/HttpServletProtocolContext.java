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

package be.fedict.eid.applet.service.impl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.shared.protocol.ProtocolContext;
import be.fedict.eid.applet.shared.protocol.ProtocolState;

/**
 * Implementation of a protocol context using the HTTP servlet session.
 * 
 * @author Frank Cornelis
 * 
 */
public class HttpServletProtocolContext implements ProtocolContext {

	public static final String PROTOCOL_STATE_SESSION_ATTRIBUTE = HttpServletProtocolContext.class
			.getName()
			+ ".state";

	private static final Log LOG = LogFactory
			.getLog(HttpServletProtocolContext.class);

	private final HttpSession session;

	/**
	 * Main constructor.
	 * 
	 * @param request
	 */
	public HttpServletProtocolContext(HttpServletRequest request) {
		this.session = request.getSession();
	}

	public ProtocolState getProtocolState() {
		ProtocolState protocolState = (ProtocolState) this.session
				.getAttribute(PROTOCOL_STATE_SESSION_ATTRIBUTE);
		LOG.debug("current protocol state: " + protocolState);
		return protocolState;
	}

	public void setProtocolState(ProtocolState protocolState) {
		LOG.debug("protocol state transition: " + protocolState);
		this.session.setAttribute(PROTOCOL_STATE_SESSION_ATTRIBUTE,
				protocolState);
	}

	public void removeProtocolState() {
		LOG.debug("removing protocol state");
		this.session.removeAttribute(PROTOCOL_STATE_SESSION_ATTRIBUTE);
	}
}
