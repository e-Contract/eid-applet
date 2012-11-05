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

package test.be.fedict.eid.applet.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.AuthenticationSignatureService;
import be.fedict.eid.applet.service.spi.DigestInfo;

@Stateless
@Local(AuthenticationSignatureService.class)
@LocalBinding(jndiBinding = "test/eid/applet/model/AuthenticationSignatureServiceBean")
public class AuthenticationSignatureServiceBean implements
		AuthenticationSignatureService {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationSignatureServiceBean.class);

	public DigestInfo preSign(List<X509Certificate> authnCertificateChain) {
		LOG.debug("preSign");
		LOG.debug("authn cert chain size: " + authnCertificateChain.size());
		byte[] wsSecurityData = "ws-security".getBytes();
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("SHA-1 error: " + e.getMessage(), e);
		}
		byte[] digestValue = messageDigest.digest(wsSecurityData);
		DigestInfo digestInfo = new DigestInfo(digestValue, "SHA-1",
				"WS-Security message");
		return digestInfo;
	}

	public void postSign(byte[] signatureValue,
			List<X509Certificate> authnCertificateChain) {
		LOG.debug("postSign: " + (signatureValue != null));

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		httpSession.setAttribute("AuthenticationSignatureValue",
				Hex.encodeHexString(signatureValue));
	}
}
