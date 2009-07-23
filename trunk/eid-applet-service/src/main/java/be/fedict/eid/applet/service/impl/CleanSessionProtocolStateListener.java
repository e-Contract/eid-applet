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

import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.impl.handler.AuthenticationDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.IdentityDataMessageHandler;
import be.fedict.eid.applet.shared.protocol.ProtocolState;
import be.fedict.eid.applet.shared.protocol.ProtocolStateListener;

/**
 * Protocol state listener that manages the cleanup of session attributes.
 * 
 * <p>
 * Removes old identity data from the session. In case something goes wrong with
 * the new identity processing we don't want to end up with a web application
 * that thinks that the citizen performed a successful identification.
 * </p>
 * 
 * @author fcorneli
 * 
 */
public class CleanSessionProtocolStateListener implements ProtocolStateListener {

	private static final Log LOG = LogFactory
			.getLog(CleanSessionProtocolStateListener.class);

	private final HttpSession httpSession;

	public CleanSessionProtocolStateListener(HttpServletRequest request) {
		this.httpSession = request.getSession();
	}

	public void protocolStateTransition(ProtocolState newProtocolState) {
		switch (newProtocolState) {
		case IDENTIFY: {
			LOG.debug("cleaning up the identity session attributes...");
			this.httpSession
					.removeAttribute(IdentityDataMessageHandler.IDENTITY_SESSION_ATTRIBUTE);
			this.httpSession
					.removeAttribute(IdentityDataMessageHandler.ADDRESS_SESSION_ATTRIBUTE);
			this.httpSession
					.removeAttribute(IdentityDataMessageHandler.PHOTO_SESSION_ATTRIBUTE);
			this.httpSession
					.removeAttribute(IdentityDataMessageHandler.EID_CERTS_SESSION_ATTRIBUTE);
			EIdData eidData = (EIdData) this.httpSession
					.getAttribute(IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE);
			if (null != eidData) {
				/*
				 * First time eidData is null.
				 */
				eidData.identity = null;
				eidData.address = null;
				eidData.photo = null;
				eidData.certs = null;
			}
			break;
		}
		case AUTHENTICATE: {
			LOG.debug("cleaning up the authn session attributes...");
			this.httpSession
					.removeAttribute(AuthenticationDataMessageHandler.AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE);
			EIdData eidData = (EIdData) this.httpSession
					.getAttribute(IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE);
			if (null != eidData) {
				eidData.identifier = null;
			}
			break;
		}
		}
	}
}
