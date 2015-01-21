/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package test.be.fedict.eid.applet.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.spi.AddressDTO;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityDTO;
import be.fedict.eid.applet.service.spi.TrustCertificateSecurityException;

@Stateless
@EJB(name = "java:global/test/UntrustedSignatureServiceBean", beanInterface = UntrustedSignatureService.class)
public class UntrustedSignatureServiceBean implements UntrustedSignatureService {

	private static final Log LOG = LogFactory
			.getLog(UntrustedSignatureServiceBean.class);

	public void postSign(byte[] signatureValue,
			List<X509Certificate> signingCertificateChain)
			throws TrustCertificateSecurityException {
		LOG.debug("postSign");

		/*
		 * Here we simulate that we don't trust the signing certificate chain.
		 */
		throw new TrustCertificateSecurityException();
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain,
			IdentityDTO identity, AddressDTO address, byte[] photo)
			throws NoSuchAlgorithmException {
		LOG.debug("preSign");

		String toBeSigned = "to be signed";
		String digestAlgo = "SHA-1";

		MessageDigest messageDigest = MessageDigest.getInstance(digestAlgo);
		byte[] digestValue = messageDigest.digest(toBeSigned.getBytes());

		String description = "Test Document";
		return new DigestInfo(digestValue, digestAlgo, description);
	}

	public String getFilesDigestAlgorithm() {
		/*
		 * We don't need file digest values.
		 */
		return null;
	}
}
