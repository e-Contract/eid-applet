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

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

/**
 * Service locator. Can handle both JNDI references as classname references.
 * Classname referencing can be useful in environments where you don't have a
 * full-blown Java EE application container available.
 * 
 * @author fcorneli
 * 
 * @param <T>
 *            the service type.
 */
public class ServiceLocator<T> {

	private final String jndiLocation;

	private final String className;

	public ServiceLocator(String initParam, ServletConfig config)
			throws ServletException {
		this.jndiLocation = config.getInitParameter(initParam);
		this.className = config.getInitParameter(initParam + "Class");
	}

	/**
	 * Locates the service. Can return <code>null</code> in case the
	 * corresponding <code>init-param</code> was not set.
	 * 
	 * @return
	 * @throws ServletException
	 */
	@SuppressWarnings("unchecked")
	public T locateService() throws ServletException {
		try {
			T service;
			if (null != this.jndiLocation) {
				InitialContext initialContext = new InitialContext();
				service = (T) initialContext.lookup(this.jndiLocation);
			} else if (null != this.className) {
				Thread currentThread = Thread.currentThread();
				ClassLoader classLoader = currentThread.getContextClassLoader();
				Class<T> serviceClass = (Class<T>) classLoader
						.loadClass(this.className);
				service = serviceClass.newInstance();
			} else {
				service = null;
			}
			return service;
		} catch (NamingException e) {
			throw new ServletException("JNDI error: " + e.getMessage(), e);
		} catch (ClassNotFoundException e) {
			throw new ServletException("Class not found: " + this.className, e);
		} catch (Exception e) {
			throw new ServletException("error: " + e.getMessage(), e);
		}
	}
}
