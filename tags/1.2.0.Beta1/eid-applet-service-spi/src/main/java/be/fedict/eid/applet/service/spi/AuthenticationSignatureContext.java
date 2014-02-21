/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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
 * Contextual state for authentication signature services.
 * 
 * @author Frank Cornelis
 * 
 */
public interface AuthenticationSignatureContext {

	/**
	 * Stores the given object.
	 * 
	 * @param name
	 * @param object
	 */
	void store(String name, Object object);

	/**
	 * Loads an object for the given name.
	 * 
	 * @param name
	 * @return
	 */
	Object load(String name);
}
