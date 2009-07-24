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

import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import be.fedict.eid.applet.service.AppletServiceServlet;

/**
 * Interface for a message handler. A message handler has the same lifecycle as
 * the {@link AppletServiceServlet} dispatcher servlet.
 * 
 * @author fcorneli
 * 
 * @param <T>
 *            the message type.
 * @see AppletServiceServlet
 */
public interface MessageHandler<T> {
	/**
	 * Handles the given message. Returns the response message to send back,
	 * this can be <code>null</code>.
	 * 
	 * @param message
	 * @param httpHeaders
	 * @param request
	 *            the request from which the body already may be consumed.
	 * @param session
	 * @return the optional response message to send back.
	 * @throws ServletException
	 */
	Object handleMessage(T message, Map<String, String> httpHeaders,
			HttpServletRequest request, HttpSession session)
			throws ServletException;

	/**
	 * Initializes this message handler.
	 * 
	 * @param config
	 * @throws ServletException
	 */
	void init(ServletConfig config) throws ServletException;
}
