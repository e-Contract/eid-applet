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

import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;

import be.fedict.eid.applet.shared.protocol.HttpTransmitter;

public class PostMethodHttpTransmitter implements HttpTransmitter {

	private final PostMethod postMethod;

	public PostMethodHttpTransmitter(PostMethod postMethod) {
		this.postMethod = postMethod;
	}

	public void addHeader(String headerName, String headerValue) {
		this.postMethod.addRequestHeader(headerName, headerValue);
	}

	public boolean isSecure() {
		try {
			return this.postMethod.getURI().getScheme().startsWith("https");
		} catch (URIException e) {
			return false;
		}
	}

	public void setBody(byte[] bodyValue) {
		RequestEntity requestEntity = new ByteArrayRequestEntity(bodyValue);
		this.postMethod.setRequestEntity(requestEntity);
	}

}
