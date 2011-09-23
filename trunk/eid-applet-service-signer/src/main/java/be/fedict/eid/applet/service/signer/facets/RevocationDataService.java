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
 * Interface for a service that retrieves revocation data about some given
 * certificate chain.
 * 
 * @author Frank Cornelis
 * 
 */
public interface RevocationDataService {

	/**
	 * Gives back the revocation data corresponding with the given certificate
	 * chain.
	 * 
	 * @param certificateChain
	 * @return
	 */
	RevocationData getRevocationData(List<X509Certificate> certificateChain);
}
