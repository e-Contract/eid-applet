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

package be.fedict.eid.applet.service.impl.handler;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.SignCertificatesDataMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

@HandlesMessage(SignCertificatesDataMessage.class)
public class SignCertificatesDataMessageHandler implements
		MessageHandler<SignCertificatesDataMessage> {

	private static final Log LOG = LogFactory
			.getLog(SignCertificatesDataMessageHandler.class);

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME)
	private boolean removeCard;

	@InitParam(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME)
	private boolean logoff;

	@InitParam(HelloMessageHandler.REQUIRE_SECURE_READER_INIT_PARAM_NAME)
	private boolean requireSecureReader;

	public Object handleMessage(SignCertificatesDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		SignatureService signatureService = this.signatureServiceLocator
				.locateService();

		List<X509Certificate> signingCertificateChain = message.certificateChain;
		X509Certificate signingCertificate = signingCertificateChain.get(0);
		if (null == signingCertificate) {
			throw new ServletException("missing non-repudiation certificate");
		}
		LOG.debug("signing certificate: "
				+ signingCertificateChain.get(0).getSubjectX500Principal());

		DigestInfo digestInfo;
		try {
			digestInfo = signatureService
					.preSign(null, signingCertificateChain);
		} catch (NoSuchAlgorithmException e) {
			throw new ServletException("no such algo: " + e.getMessage(), e);
		}

		// also save it in the session for later verification
		SignatureDataMessageHandler.setDigestValue(digestInfo.digestValue,
				session);

		SignRequestMessage signRequestMessage = new SignRequestMessage(
				digestInfo.digestValue, digestInfo.digestAlgo,
				digestInfo.description, this.logoff, this.removeCard,
				this.requireSecureReader);
		return signRequestMessage;
	}

	public void init(ServletConfig config) throws ServletException {
		// empty
	}
}
