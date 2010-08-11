/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

package be.fedict.eid.applet.service.signer.facets;

/**
 * Interface for a time-stamp service.
 * 
 * @author Frank Cornelis
 * 
 */
public interface TimeStampService {

	/**
	 * Gives back the encoded time-stamp token for the given array of data
	 * bytes.
	 * 
	 * @param data
	 *            the data to be time-stamped.
	 * @return
	 * @throws Exception
	 *             in case something went wrong.
	 */
	byte[] timeStamp(byte[] data) throws Exception;
}
