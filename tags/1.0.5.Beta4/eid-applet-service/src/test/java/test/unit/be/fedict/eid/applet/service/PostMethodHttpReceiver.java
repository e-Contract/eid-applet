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

package test.unit.be.fedict.eid.applet.service;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.methods.PostMethod;

import be.fedict.eid.applet.shared.protocol.HttpReceiver;

public class PostMethodHttpReceiver implements HttpReceiver {

	private final PostMethod postMethod;

	public PostMethodHttpReceiver(PostMethod postMethod) {
		this.postMethod = postMethod;
	}

	public byte[] getBody() {
		try {
			return this.postMethod.getResponseBody();
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
	}

	public List<String> getHeaderNames() {
		List<String> headerNames = new LinkedList<String>();
		Header[] responseHeaders = this.postMethod.getResponseHeaders();
		for (Header responseHeader : responseHeaders) {
			headerNames.add(responseHeader.getName());
		}
		return headerNames;
	}

	public String getHeaderValue(String headerName) {
		return this.postMethod.getResponseHeader(headerName).getValue();
	}

	public boolean isSecure() {
		return true;
	}
}
