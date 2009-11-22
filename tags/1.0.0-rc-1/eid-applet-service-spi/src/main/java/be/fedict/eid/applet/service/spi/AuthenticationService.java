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
 * Interface for authentication service components.
 * 
 * @author Frank Cornelis
 * 
 */
public interface AuthenticationService {

	/**
	 * Validates the given certificate chain. After the eID Applet Service has
	 * verified the authentication signature, it will invoke this method on your
	 * authentication service component. The implementation of this method
	 * should validate the given certificate chain. This validation could be
	 * based on PKI validation, or could be based on simply trusting the
	 * incoming public key. The actual implementation is very dependent on your
	 * type of application. This method should only be used for certificate
	 * validation. Processing the incoming citizen identifier (if required at
	 * all) should be handled as part of the eID Applet target page.
	 * 
	 * <p>
	 * Check out <a href="http://code.google.com/p/jtrust/">jTrust</a> for an
	 * implementation of a PKI validation framework.
	 * </p>
	 * 
	 * @param certificateChain
	 *            the X509 authentication certificate chain of the citizen.
	 * @throws SecurityException
	 *             in case the certificate chain is invalid/not accepted.
	 */
	void validateCertificateChain(List<X509Certificate> certificateChain)
			throws SecurityException;
}
