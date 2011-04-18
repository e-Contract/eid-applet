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
 * Interface for the signature policy service.
 * 
 * @author Frank Cornelis
 * 
 */
public interface SignaturePolicyService {

	/**
	 * Gives back the signature policy identifier URI.
	 * 
	 * @return
	 */
	String getSignaturePolicyIdentifier();

	/**
	 * Gives back the short description of the signature policy or
	 * <code>null</code> if a description is not available.
	 * 
	 * @return the description, or <code>null</code>.
	 */
	String getSignaturePolicyDescription();

	/**
	 * Gives back the download URL where the signature policy document can be
	 * found. Can be <code>null</code> in case such a download location does not
	 * exist.
	 * 
	 * @return the download URL, or <code>null</code>.
	 */
	String getSignaturePolicyDownloadUrl();

	/**
	 * Gives back the signature policy document.
	 * 
	 * @return the bytes of the signature policy document.
	 */
	byte[] getSignaturePolicyDocument();
}
