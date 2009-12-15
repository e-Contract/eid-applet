/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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
 * Service Provider Interface for the privacy service.
 * 
 * @author Frank Cornelis
 * 
 */
public interface PrivacyService {

	/**
	 * Gives back the usage description on the retrieved identity data.
	 * 
	 * @param language
	 *            the optional language indication.
	 * @return the usage description.
	 */
	String getIdentityDataUsage(String language);
}
