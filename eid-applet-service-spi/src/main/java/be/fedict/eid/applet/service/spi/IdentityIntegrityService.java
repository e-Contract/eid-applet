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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for identity integrity service components. Can be used by the eID
 * Applet Service to run integrity validation on the identity data that comes
 * from the eID card.
 * 
 * @author Frank Cornelis
 * 
 */
public interface IdentityIntegrityService {

	/**
	 * Checks the validity of the National Registration certificate. After the
	 * eID Applet Service has performed the integrity checks on the incoming
	 * identity data files it will invoke this method on your component. Your
	 * implementation should check the validity of the given national
	 * registration certificate. This method should only be used to validation
	 * the national registration certificate. Processing the incoming identity
	 * data should be handled as part of the eID Applet target page.
	 * 
	 * <p>
	 * Check out <a href="http://code.google.com/p/jtrust/">jTrust</a> for an
	 * implementation of a PKI validation framework.
	 * </p>
	 * 
	 * @param certificateChain
	 *            the national registration X509 certificate chain.
	 * @throws SecurityException
	 *             in case the certificate is invalid/not accepted.
	 */
	void checkNationalRegistrationCertificate(
			List<X509Certificate> certificateChain) throws SecurityException;
}
