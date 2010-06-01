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

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;

import be.fedict.eid.applet.shared.protocol.HttpTransmitter;

/**
 * Implementation of an {@link HttpTransmitter} using {@link HttpURLConnection}.
 * 
 * @author Frank Cornelis
 * 
 */
public class HttpURLConnectionHttpTransmitter implements HttpTransmitter {

	private final HttpURLConnection connection;

	/**
	 * Main constructor.
	 * 
	 * @param connection
	 */
	public HttpURLConnectionHttpTransmitter(HttpURLConnection connection) {
		this.connection = connection;
		this.connection.setUseCaches(false);
		this.connection.setAllowUserInteraction(false);
		this.connection.setRequestProperty("Content-Type",
				"application/octet-stream");
		this.connection.setDoInput(true);
		this.connection.setDoOutput(true);
		try {
			this.connection.setRequestMethod("POST");
		} catch (ProtocolException e) {
			throw new RuntimeException("protocol error: " + e.getMessage(), e);
		}
	}

	public void addHeader(String headerName, String headerValue) {
		this.connection.setRequestProperty(headerName, headerValue);
	}

	public void setBody(byte[] bodyValue) {
		OutputStream connectionOutputStream;
		try {
			connectionOutputStream = this.connection.getOutputStream();
			connectionOutputStream.write(bodyValue);
			connectionOutputStream.close();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		} catch (Exception e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}
	}

	public boolean isSecure() {
		if ("localhost".equals(this.connection.getURL().getHost())) {
			/*
			 * We trust localhost web applications.
			 */
			return true;
		}
		if (false == "https".equals(this.connection.getURL().getProtocol())) {
			/*
			 * Never trust the other side. We really need the SSL secure channel
			 * to communicate data between eID Applet and service.
			 */
			return false;
		}
		return true;
	}
}
