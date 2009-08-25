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

/**
 * Interface for HTTP transmitter component.
 * 
 * @author Frank Cornelis
 * 
 */
public interface HttpTransmitter {

	/**
	 * Checks whether the HTTP transmitter component is using a secure SSL
	 * channel.
	 * 
	 * @return
	 */
	boolean isSecure();

	/**
	 * Adds a HTTP header to the transport component.
	 * 
	 * @param headerName
	 * @param headerValue
	 */
	void addHeader(String headerName, String headerValue);

	/**
	 * Sets the HTTP body of the transport component. If this method is being
	 * invoked this will always take place after all
	 * {@link #addHeader(String, String)} invocations.
	 * 
	 * @param bodyValue
	 * 
	 * @see #addHeader(String, String)
	 */
	void setBody(byte[] bodyValue);
}
