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

/*
 * Copyright (C) 2008-2009 FedICT.
 * This file is part of the eID Applet Project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package be.fedict.eid.applet.service.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Implementation of a temporary data storage using the HTTP session as
 * temporary repository.
 * 
 * @author Frank Cornelis
 * 
 */
public class HttpSessionTemporaryDataStorage implements TemporaryDataStorage {

	private static final Log LOG = LogFactory
			.getLog(HttpSessionTemporaryDataStorage.class);

	public static final String TEMP_OUTPUT_STREAM_ATTRIBUTE = HttpSessionTemporaryDataStorage.class
			.getName()
			+ ".tempData";

	public static final String TEMP_ATTRIBUTES_ATTRIBUTE = HttpSessionTemporaryDataStorage.class
			.getName()
			+ ".tempAttribs";

	public InputStream getTempInputStream() {
		LOG.debug("get temp input stream");
		HttpSession httpSession = getHttpSession();
		ByteArrayOutputStream tempOutputStream = (ByteArrayOutputStream) httpSession
				.getAttribute(TEMP_OUTPUT_STREAM_ATTRIBUTE);
		if (null == tempOutputStream) {
			LOG.warn("missing temp output stream");
			return null;
		}
		byte[] tempData = tempOutputStream.toByteArray();
		ByteArrayInputStream tempInputStream = new ByteArrayInputStream(
				tempData);
		return tempInputStream;
	}

	public OutputStream getTempOutputStream() {
		LOG.debug("get new temp output stream");
		HttpSession httpSession = getHttpSession();
		ByteArrayOutputStream tempOutputStream = new ByteArrayOutputStream();
		httpSession
				.setAttribute(TEMP_OUTPUT_STREAM_ATTRIBUTE, tempOutputStream);
		return tempOutputStream;
	}

	/**
	 * Gives back the current HTTP session using JACC.
	 * 
	 * @return
	 */
	public static HttpSession getHttpSession() {
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		return httpSession;
	}

	@SuppressWarnings("unchecked")
	private Map<String, Serializable> getAttributes() {
		HttpSession httpSession = getHttpSession();
		Map<String, Serializable> attributes = (Map<String, Serializable>) httpSession
				.getAttribute(TEMP_ATTRIBUTES_ATTRIBUTE);
		if (null != attributes) {
			return attributes;
		}
		attributes = new HashMap<String, Serializable>();
		httpSession.setAttribute(TEMP_ATTRIBUTES_ATTRIBUTE, attributes);
		return attributes;
	}

	public Serializable getAttribute(String attributeName) {
		Map<String, Serializable> attributes = getAttributes();
		return attributes.get(attributeName);
	}

	public void setAttribute(String attributeName, Serializable attributeValue) {
		Map<String, Serializable> attributes = getAttributes();
		attributes.put(attributeName, attributeValue);
	}
}
