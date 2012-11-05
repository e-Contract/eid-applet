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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Authentication Signature Service SPI. Via this interface you can create for
 * example WS-Security signatures via the eID Applet.
 * 
 * @author Frank Cornelis
 * 
 */
public interface AuthenticationSignatureService {

	/**
	 * Gives back the digest value and digest algo to be used by the eID Applet
	 * for the creation of an authentication signature.
	 * 
	 * @param authnCertificateChain
	 *            the authentication certificate chain.
	 * @return the digest info structure.
	 */
	DigestInfo preSign(List<X509Certificate> authnCertificateChain);

	/**
	 * Via this method your receive the signature as created via the eID Applet
	 * over the corresponding digest value from the {@link DigestInfo} structure
	 * from {@link #preSign(List)}.
	 * 
	 * @param signatureValue
	 *            the signature value.
	 * @param authnCertificateChain
	 *            the authentication certificate chain.
	 */
	void postSign(byte[] signatureValue,
			List<X509Certificate> authnCertificateChain);
}
