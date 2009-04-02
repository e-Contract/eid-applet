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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.spi.AuditService;
import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.eid.applet.shared.AuthenticationContract;
import be.fedict.eid.applet.shared.AuthenticationDataMessage;
import be.fedict.eid.applet.shared.FinishedMessage;

/**
 * Authentication data message protocol handler.
 * 
 * @author fcorneli
 * 
 */
public class AuthenticationDataMessageHandler implements
		MessageHandler<AuthenticationDataMessage> {

	public static final String AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE = "eid.identifier";

	private static final Log LOG = LogFactory
			.getLog(AuthenticationDataMessageHandler.class);

	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	private ServiceLocator<AuditService> auditServiceLocator;

	private String hostname;

	private InetAddress inetAddress;

	public static final String AUTHN_SERVICE_INIT_PARAM_NAME = "AuthenticationService";

	public static final String AUDIT_SERVICE_INIT_PARAM_NAME = "AuditService";

	public static final String AUTHN_CHALLENGE_SESSION_ATTRIBUTE = AuthenticationDataMessageHandler.class
			.getName()
			+ ".authnChallence";

	public Object handleMessage(AuthenticationDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("authentication data message received");

		byte[] signatureValue = message.signatureValue;
		List<X509Certificate> certificateChain = message.certificateChain;
		X509Certificate signingCertificate = certificateChain.get(0);
		LOG.debug("authn signing certificate: " + signingCertificate);
		PublicKey signingKey = signingCertificate.getPublicKey();

		byte[] challenge = AuthenticationDataMessageHandler
				.getAuthnChallenge(session);
		AuthenticationContract authenticationContract = new AuthenticationContract(
				message.saltValue, this.hostname, this.inetAddress, challenge);
		byte[] toBeSigned;
		try {
			toBeSigned = authenticationContract.calculateToBeSigned();
		} catch (IOException e) {
			throw new ServletException("IO error: " + e.getMessage(), e);
		}

		try {
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(signingKey);
			signature.update(toBeSigned);
			boolean result = signature.verify(signatureValue);
			if (false == result) {
				AuditService auditService = this.auditServiceLocator
						.locateService();
				if (null != auditService) {
					String remoteAddress = request.getRemoteAddr();
					auditService.authenticationError(remoteAddress,
							signingCertificate);
				}
				throw new SecurityException("authn signature incorrect");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException("algo error");
		} catch (InvalidKeyException e) {
			throw new SecurityException("authn key error");
		} catch (SignatureException e) {
			throw new SecurityException("signature error");
		}

		AuthenticationService authenticationService = this.authenticationServiceLocator
				.locateService();
		authenticationService.validateCertificateChain(certificateChain);

		/*
		 * Push authenticated used Id into the HTTP session.
		 */
		String userId = UserIdentifierUtil.getUserId(signingCertificate);

		/*
		 * Some people state that you cannot use the national register number
		 * without hashing. Problem is that hashing introduces hash collision
		 * problems. The probability is very low, but what if it's your leg
		 * they're cutting of because of a patient mismatch based on the SHA1 of
		 * your national register number?
		 */
		session.setAttribute(AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE,
				userId);

		EIdData eidData = (EIdData) session
				.getAttribute(IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE);
		if (null == eidData) {
			eidData = new EIdData();
			session.setAttribute(
					IdentityDataMessageHandler.EID_SESSION_ATTRIBUTE, eidData);
		}
		eidData.identifier = userId;

		AuditService auditService = this.auditServiceLocator.locateService();
		if (null != auditService) {
			auditService.authenticated(userId);
		}

		return new FinishedMessage();
	}

	public void init(ServletConfig config) throws ServletException {
		this.authenticationServiceLocator = new ServiceLocator<AuthenticationService>(
				AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME,
				config);

		this.auditServiceLocator = new ServiceLocator<AuditService>(
				AuthenticationDataMessageHandler.AUDIT_SERVICE_INIT_PARAM_NAME,
				config);

		this.hostname = config
				.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME);

		String inetAddress = config
				.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME);
		if (null != inetAddress) {
			try {
				this.inetAddress = InetAddress.getByName(inetAddress);
			} catch (UnknownHostException e) {
				throw new ServletException("unknown host: " + inetAddress);
			}
		}
	}

	public static void setAuthnChallenge(byte[] challenge, HttpSession session) {
		session
				.setAttribute(
						AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE,
						challenge);
	}

	public static byte[] getAuthnChallenge(HttpSession session) {
		byte[] challenge = (byte[]) session
				.getAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE);
		session
				.removeAttribute(AuthenticationDataMessageHandler.AUTHN_CHALLENGE_SESSION_ATTRIBUTE);
		return challenge;
	}
}
