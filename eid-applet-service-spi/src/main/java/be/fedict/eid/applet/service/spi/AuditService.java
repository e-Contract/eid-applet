/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2009 Frank Cornelis.
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
 * Interface for audit service components. Via such a component you can receive
 * eID Applet Service security related events.
 * 
 * @author Frank Cornelis
 * 
 */
public interface AuditService {

	/**
	 * Called by the eID Applet Service in case a citizen has been successfully
	 * authenticated using the eID Applet.
	 * 
	 * @param userId
	 *            the unique identifier of the authenticated user.
	 */
	void authenticated(String userId);

	/**
	 * Called by the eID Applet Service in case a citizen has been successfully
	 * identified using the eID Applet.
	 * 
	 * @param userId
	 *            the unique identifier of the identified user.
	 */
	void identified(String userId);

	/**
	 * Called by the eID Applet Service in case the eID Applet responded with an
	 * invalid authentication signature.
	 * 
	 * @param remoteAddress
	 *            the remote address of the client causing the authentication
	 *            error.
	 * @param clientCertificate
	 *            the X509 certificate causing the authentication error.
	 */
	void authenticationError(String remoteAddress,
			X509Certificate clientCertificate);

	/**
	 * Called by the eID Applet Service in case the eID Applet detects an
	 * integrity error during the identity data verification.
	 * 
	 * @param remoteAddress
	 *            the remote address of the client causing the integrity error.
	 */
	void identityIntegrityError(String remoteAddress);

	/**
	 * Called by the eID Applet Service in case the eID Applet responded with an
	 * invalid non-repudiation signature.
	 * 
	 * @param remoteAddress
	 *            the remote address of the client causing the signature error.
	 * @param clientCertificate
	 *            the X509 certificate causing the signature error.
	 */
	void signatureError(String remoteAddress, X509Certificate clientCertificate);

	/**
	 * Called by the eID Applet Service in case a user created a non-repudiation
	 * signature.
	 * 
	 * @param userId
	 *            the unique identifier of the user creating a non-repudiation
	 *            signature.
	 */
	void signed(String userId);
}
