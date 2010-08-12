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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for trust validator of a TSP.
 * 
 * @author Frank Cornelis
 * 
 */
public interface TimeStampServiceValidator {

	/**
	 * Validates the given certificate chain.
	 * 
	 * @param certificateChain
	 * @param revocationData
	 *            the optional data container that should be filled with
	 *            revocation data that was used to validate the given
	 *            certificate chain.
	 * @throws Exception
	 *             in case the certificate chain is invalid.
	 */
	void validate(List<X509Certificate> certificateChain,
			RevocationData revocationData) throws Exception;
}
