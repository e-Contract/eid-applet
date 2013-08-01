/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for extended signature service component.
 * 
 * @author Frank Cornelis
 * 
 */
public interface SignatureServiceEx extends SignatureService {

	/**
	 * Pre-sign callback method. Depending on the configuration some parameters
	 * are passed. The returned value will be signed by the eID Applet.
	 * 
	 * <p>
	 * TODO: service must be able to throw some exception on failure.
	 * </p>
	 * 
	 * @param digestInfos
	 *            the optional list of digest infos.
	 * @param signingCertificateChain
	 *            the optional list of certificates.
	 * @param identity
	 *            the optional identity.
	 * @param address
	 *            the optional identity address.
	 * @param photo
	 *            the optional identity photo.
	 * @return the digest to be signed.
	 * @throws NoSuchAlgorithmException
	 */
	DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain,
			IdentityDTO identity, AddressDTO address, byte[] photo)
			throws NoSuchAlgorithmException;
}
