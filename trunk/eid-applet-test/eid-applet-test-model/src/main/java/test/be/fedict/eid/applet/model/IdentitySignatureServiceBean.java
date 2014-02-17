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
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import be.fedict.eid.applet.service.spi.AddressDTO;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityDTO;

@Stateless
@EJB(name = "java:global/test/IdentitySignatureServiceBean", beanInterface = IdentitySignatureService.class)
public class IdentitySignatureServiceBean implements IdentitySignatureService {

	private static final Log LOG = LogFactory
			.getLog(IdentitySignatureServiceBean.class);

	public void postSign(byte[] signatureValue,
			List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");

		String signatureValueStr = new String(Hex.encodeHex(signatureValue));

		HttpSession session = getHttpSession();
		session.setAttribute("SignatureValue", signatureValueStr);
		session.setAttribute("SigningCertificateChain", signingCertificateChain);
	}

	private HttpSession getHttpSession() {
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}
		HttpSession httpSession = httpServletRequest.getSession();
		return httpSession;
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain,
			IdentityDTO identity, AddressDTO address, byte[] photo)
			throws NoSuchAlgorithmException {
		LOG.debug("preSign (ex)");

		String toBeSigned = identity.name + address.city;
		String digestAlgo = "SHA-1";

		HttpSession httpSession = getHttpSession();
		httpSession.setAttribute("IdentityName", identity.name);
		httpSession.setAttribute("IdentityCity", address.city);

		MessageDigest messageDigest = MessageDigest.getInstance(digestAlgo,
				new BouncyCastleProvider());
		byte[] digestValue = messageDigest.digest(toBeSigned.getBytes());

		String description = "Test Text Document";
		return new DigestInfo(digestValue, digestAlgo, description);
	}

	public String getFilesDigestAlgorithm() {
		/*
		 * We don't need file digest values.
		 */
		return null;
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain)
			throws NoSuchAlgorithmException {
		throw new UnsupportedOperationException(
				"this is a SignatureServiceEx implementation");
	}
}
