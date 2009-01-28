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

package be.fedict.eid.applet.service.impl;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.util.Arrays;

import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.SignatureDataMessage;

/**
 * Signature data message protocol handler.
 * 
 * @author fcorneli
 * 
 */
public class SignatureDataMessageHandler implements
		MessageHandler<SignatureDataMessage> {

	private static final Log LOG = LogFactory
			.getLog(SignatureDataMessageHandler.class);

	private ServiceLocator<SignatureService> signatureServiceLocator;

	public Object handleMessage(SignatureDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("signature data message received");

		byte[] signatureValue = message.signatureValue;
		List<X509Certificate> certificateChain = message.certificateChain;
		X509Certificate signingCertificate = certificateChain.get(0);
		LOG.debug("non-repudiation signing certificate: " + signingCertificate);
		PublicKey signingPublicKey = signingCertificate.getPublicKey();

		/*
		 * Verify the signature.
		 */
		byte[] expectedDigestValue = HelloMessageHandler
				.getDigestValue(session);
		byte[] signatureDigestValue;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, signingPublicKey);
			byte[] signatureDigestInfoValue = cipher.doFinal(signatureValue);
			ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
			DigestInfo signatureDigestInfo = new DigestInfo((ASN1Sequence) aIn
					.readObject());
			signatureDigestValue = signatureDigestInfo.getDigest();
		} catch (Exception e) {
			throw new RuntimeException("signature verification error: "
					+ e.getMessage(), e);
		}

		if (false == Arrays.areEqual(expectedDigestValue, signatureDigestValue)) {
			throw new RuntimeException("signature incorrect");
		}
		// no need to also check the digest algo

		SignatureService signatureService = this.signatureServiceLocator
				.locateService();
		signatureService.postSign(signatureValue, certificateChain);

		return new FinishedMessage();
	}

	public void init(ServletConfig config) throws ServletException {
		this.signatureServiceLocator = new ServiceLocator<SignatureService>(
				HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME, config);
	}
}
