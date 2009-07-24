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

import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;

import be.fedict.eid.applet.shared.protocol.HttpReceiver;

/**
 * HttpServletRequest based HTTP receiver.
 * 
 * @author fcorneli
 * 
 */
public class HttpServletRequestHttpReceiver implements HttpReceiver {

	private final HttpServletRequest httpServletRequest;

	/**
	 * Main constructor.
	 * 
	 * @param httpServletRequest
	 */
	public HttpServletRequestHttpReceiver(HttpServletRequest httpServletRequest) {
		this.httpServletRequest = httpServletRequest;
	}

	public byte[] getBody() {
		try {
			ServletInputStream inputStream = this.httpServletRequest
					.getInputStream();
			byte[] body = IOUtils.toByteArray(inputStream);
			return body;
		} catch (IOException e) {
			throw new RuntimeException("IO error: " + e.getMessage(), e);
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> getHeaderNames() {
		Enumeration headerNamesEnumeration = this.httpServletRequest
				.getHeaderNames();
		List<String> headerNames = new LinkedList<String>();
		while (headerNamesEnumeration.hasMoreElements()) {
			String headerName = (String) headerNamesEnumeration.nextElement();
			headerNames.add(headerName);
		}
		return headerNames;
	}

	public String getHeaderValue(String headerName) {
		return this.httpServletRequest.getHeader(headerName);
	}

	public boolean isSecure() {
		if (false == this.httpServletRequest.isSecure()) {
			return false;
		}
		return true;
	}
}
