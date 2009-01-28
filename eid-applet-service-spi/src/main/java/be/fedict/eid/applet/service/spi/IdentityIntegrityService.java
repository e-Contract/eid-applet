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

/**
 * Interface for identity integrity service components. Can be used by the eID
 * Applet Service to run integrity validation on the identity data that comes
 * from the eID card.
 * 
 * @author fcorneli
 * 
 */
public interface IdentityIntegrityService {

	/**
	 * Checks the validity of the National Registry certificate.
	 * 
	 * @param certificate
	 * @throws SecurityException
	 *             in case the certificate is invalid/not accepted.
	 */
	void checkNationalRegistryCertificate(X509Certificate certificate)
			throws SecurityException;
}
