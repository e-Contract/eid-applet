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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import be.fedict.eid.applet.shared.protocol.HttpReceiver;

public class HttpURLConnectionHttpReceiver implements HttpReceiver {

	private final HttpURLConnection connection;

	public HttpURLConnectionHttpReceiver(HttpURLConnection connection) {
		this.connection = connection;
	}

	public byte[] getBody() {
		try {
			InputStream inputStream = this.connection.getInputStream();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int n;
			do {
				n = inputStream.read(buffer);
				if (-1 != n) {
					baos.write(buffer, 0, n);
				}
			} while (-1 != n);
			return baos.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage());
		}
	}

	public List<String> getHeaderNames() {
		Map<String, List<String>> headerFields = this.connection
				.getHeaderFields();
		List<String> headerNames = new LinkedList<String>();
		for (String headerName : headerFields.keySet()) {
			if (null == headerName) {
				/*
				 * headerName = null is the response status code. Nasty API
				 * feature.
				 */
				continue;
			}
			headerNames.add(headerName);
		}
		return headerNames;
	}

	public String getHeaderValue(String headerName) {
		return this.connection.getHeaderField(headerName);
	}

	public boolean isSecure() {
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