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

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;

public class HttpTestSession implements HttpSession {

	private final Map<String, Object> attributes;

	public HttpTestSession() {
		this.attributes = new HashMap<String, Object>();
	}

	public Object getAttribute(String name) {
		return this.attributes.get(name);
	}

	public Enumeration getAttributeNames() {
		return null;
	}

	public long getCreationTime() {
		return 0;
	}

	public String getId() {
		return null;
	}

	public long getLastAccessedTime() {
		return 0;
	}

	public int getMaxInactiveInterval() {
		return 0;
	}

	public ServletContext getServletContext() {
		return null;
	}

	public HttpSessionContext getSessionContext() {
		return null;
	}

	public Object getValue(String name) {
		return null;
	}

	public String[] getValueNames() {
		return null;
	}

	public void invalidate() {
	}

	public boolean isNew() {
		return false;
	}

	public void putValue(String name, Object value) {
	}

	public void removeAttribute(String name) {
	}

	public void removeValue(String name) {
		this.attributes.remove(name);
	}

	public void setAttribute(String name, Object value) {
		this.attributes.put(name, value);
	}

	public void setMaxInactiveInterval(int interval) {
	}
}
