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

package be.fedict.eid.applet.service.spi;

/**
 * Insecure Client Environment Exception.
 * 
 * @author Frank Cornelis
 * 
 */
public class InsecureClientEnvironmentException extends Exception {

	private static final long serialVersionUID = 1L;

	private final boolean warnOnly;

	/**
	 * Default constructor.
	 */
	public InsecureClientEnvironmentException() {
		this(false);
	}

	/**
	 * Main constructor.
	 * 
	 * @param warnOnly
	 *            only makes that the citizen is warned about a possible
	 *            insecure enviroment.
	 */
	public InsecureClientEnvironmentException(boolean warnOnly) {
		this.warnOnly = warnOnly;
	}

	/**
	 * If set the eID Applet will only give a warning on case the server-side
	 * marks the client environment as being insecure. Else the eID Applet will
	 * abort the requested eID operation.
	 * 
	 * @return <code>true</code> if the applet should only give a warning,
	 *         <code>false</code> otherwise.
	 */
	public boolean isWarnOnly() {
		return this.warnOnly;
	}
}
