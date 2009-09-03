/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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

import be.fedict.eid.applet.beta.TempFileManager;

/**
 * Temporary file manager listener. Triggers the clean up of the temporary
 * files.
 * 
 * @author Frank Cornelis
 * 
 */
public class TempFileManagerListener implements HttpSessionListener {

	private static final Log LOG = LogFactory
			.getLog(TempFileManagerListener.class);

	@EJB
	private TempFileManager tempFileManager;

	public void sessionCreated(HttpSessionEvent event) {
		LOG.debug("session created");
	}

	public void sessionDestroyed(HttpSessionEvent event) {
		LOG.debug("session destroyed");
		HttpSession httpSession = event.getSession();
		this.tempFileManager.cleanup(httpSession);
	}
}
