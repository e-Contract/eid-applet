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

package be.fedict.eid.applet.beta.webapp;

import javax.ejb.EJB;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.beta.SessionContextManager;

public class SessionContextListener implements HttpSessionListener {

	private static final Log LOG = LogFactory
			.getLog(SessionContextListener.class);

	@EJB
	private SessionContextManager sessionContextManager;

	public void sessionCreated(HttpSessionEvent event) {
		HttpSession session = event.getSession();
		String sessionId = session.getId();
		LOG.debug("session created: " + sessionId);
		int contextId = this.sessionContextManager.getSessionContextId(sessionId);
		LOG.debug("context Id: " + contextId);
	}

	public void sessionDestroyed(HttpSessionEvent event) {
		HttpSession session = event.getSession();
		String sessionId = session.getId();
		LOG.debug("session destroyed: " + sessionId);
		this.sessionContextManager.deactivateSessionContext(sessionId);
	}
}
