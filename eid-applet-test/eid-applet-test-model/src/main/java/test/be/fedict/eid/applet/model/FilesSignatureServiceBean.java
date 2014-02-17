/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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
import java.util.LinkedList;
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

import be.fedict.eid.applet.service.spi.DigestInfo;

@Stateless
@EJB(name = "java:global/test/FilesSignatureServiceBean", beanInterface = FilesSignatureService.class)
public class FilesSignatureServiceBean implements FilesSignatureService {

	private static final Log LOG = LogFactory
			.getLog(FilesSignatureServiceBean.class);

	public void postSign(byte[] signatureValue,
			List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		String signatureValueStr = new String(Hex.encodeHex(signatureValue));

		HttpSession session = httpServletRequest.getSession();
		session.setAttribute("SignatureValue", signatureValueStr);
		session.setAttribute("SigningCertificateChain", signingCertificateChain);
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain)
			throws NoSuchAlgorithmException {
		LOG.debug("preSign");

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession session = httpServletRequest.getSession();
		String signDigestAlgo = (String) session.getAttribute("signDigestAlgo");
		LOG.debug("signature digest algo: " + signDigestAlgo);

		List<String> fileDescriptions = new LinkedList<String>();
		MessageDigest messageDigest = MessageDigest.getInstance(signDigestAlgo);
		for (DigestInfo digestInfo : digestInfos) {
			LOG.debug("processing digest for: " + digestInfo.description);
			fileDescriptions.add(digestInfo.description + "\n");
			messageDigest.update(digestInfo.digestValue);
			/*
			 * XMLDSig, XAdES or PDF is possible here...
			 */
		}
		byte[] digestValue = messageDigest.digest();

		session.setAttribute("signedFiles", fileDescriptions);

		String description = "Local Test Files";
		return new DigestInfo(digestValue, signDigestAlgo, description);
	}

	public String getFilesDigestAlgorithm() {
		LOG.debug("getFileDigestAlgoritm()");
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession session = httpServletRequest.getSession();
		String filesDigestAlgo = (String) session
				.getAttribute("filesDigestAlgo");
		LOG.debug("files digest algo: " + filesDigestAlgo);

		return filesDigestAlgo;
	}
}
