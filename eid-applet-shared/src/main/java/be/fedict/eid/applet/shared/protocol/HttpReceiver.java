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

package be.fedict.eid.applet.shared.protocol;

import java.util.List;

/**
 * Interface for HTTP receiver component.
 * 
 * @author Frank Cornelis
 * 
 */
public interface HttpReceiver {

	/**
	 * Checks whether the HTTP receiver is using a secured SSL channel.
	 * 
	 * @return
	 */
	boolean isSecure();

	/**
	 * Gives back all HTTP header names.
	 * 
	 * @return
	 */
	List<String> getHeaderNames();

	/**
	 * Gives back a specific HTTP header value.
	 * 
	 * @param headerName
	 * @return
	 */
	String getHeaderValue(String headerName);

	/**
	 * Gives back the HTTP body. Can be <code>null</code> in case no body was
	 * present.
	 * 
	 * @return
	 */
	byte[] getBody();
}
