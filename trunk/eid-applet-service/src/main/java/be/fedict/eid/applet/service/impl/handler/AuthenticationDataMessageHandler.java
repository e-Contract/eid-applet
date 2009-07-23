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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;

import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.impl.AuthenticationChallenge;
import be.fedict.eid.applet.service.impl.MessageHandler;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.impl.UserIdentifierUtil;
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

	private Long maxMaturity;

	private byte[] encodedServerCertificate;

	private boolean sessionIdChannelBinding;

	public static final String AUTHN_SERVICE_INIT_PARAM_NAME = "AuthenticationService";

	public static final String AUDIT_SERVICE_INIT_PARAM_NAME = "AuditService";

	public static final String CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME = "ChallengeMaxMaturity";

	public static final String NRCID_SECRET_INIT_PARAM_NAME = "NRCIDSecret";

	public static final String NRCID_ORG_ID_INIT_PARAM_NAME = "NRCIDOrgId";

	public static final String NRCID_APP_ID_INIT_PARAM_NAME = "NRCIDAppId";

	private String nrcidSecret;

	private String nrcidOrgId;

	private String nrcidAppId;

	public Object handleMessage(AuthenticationDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("authentication data message received");

		byte[] signatureValue = message.signatureValue;
		List<X509Certificate> certificateChain = message.certificateChain;
		X509Certificate signingCertificate = certificateChain.get(0);
		LOG.debug("authn signing certificate subject: "
				+ signingCertificate.getSubjectX500Principal());
		PublicKey signingKey = signingCertificate.getPublicKey();

		if (this.sessionIdChannelBinding) {
			checkSessionIdChannelBinding(message, request);
			if (null == this.encodedServerCertificate) {
				LOG
						.warn("adviced to use in combination with server certificate channel binding");
			}
		}

		if (null != this.encodedServerCertificate) {
			LOG.debug("using server certificate channel binding");
		}

		if (false == this.sessionIdChannelBinding
				&& null == this.encodedServerCertificate) {
			LOG.warn("no using any secure channel binding");
		}

		byte[] challenge;
		try {
			challenge = AuthenticationChallenge.getAuthnChallenge(session,
					maxMaturity);
		} catch (SecurityException e) {
			AuditService auditService = this.auditServiceLocator
					.locateService();
			if (null != auditService) {
				String remoteAddress = request.getRemoteAddr();
				auditService.authenticationError(remoteAddress,
						signingCertificate);
			}
			throw new ServletException("security error: " + e.getMessage(), e);
		}
		AuthenticationContract authenticationContract = new AuthenticationContract(
				message.saltValue, this.hostname, this.inetAddress,
				message.sessionId, this.encodedServerCertificate, challenge);
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

		String userId = UserIdentifierUtil.getUserId(signingCertificate);
		if (null != this.nrcidSecret) {
			userId = UserIdentifierUtil.getNonReversibleCitizenIdentifier(
					userId, this.nrcidOrgId, this.nrcidAppId, this.nrcidSecret);
		}
		/*
		 * Some people state that you cannot use the national register number
		 * without hashing. Problem is that hashing introduces hash collision
		 * problems. The probability is very low, but what if it's your leg
		 * they're cutting of because of a patient mismatch based on the SHA1 of
		 * your national register number?
		 */

		/*
		 * Push authenticated used Id into the HTTP session.
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

	private void checkSessionIdChannelBinding(
			AuthenticationDataMessage message, HttpServletRequest request) {
		LOG.debug("using TLS session Id channel binding");
		byte[] sessionId = message.sessionId;
		/*
		 * Next is Tomcat specific.
		 */
		String actualSessionId = (String) request
				.getAttribute("javax.servlet.request.ssl_session");
		if (null == actualSessionId) {
			/*
			 * Servlet specs v3.0
			 */
			actualSessionId = (String) request
					.getAttribute("javax.servlet.request.ssl_session_id");
		}
		if (null == actualSessionId) {
			LOG.warn("could not verify the SSL session identifier");
			return;
		}
		if (false == Arrays.equals(sessionId, Hex.decode(actualSessionId))) {
			LOG.warn("SSL session Id mismatch");
			LOG.debug("signed SSL session Id: "
					+ new String(Hex.encode(sessionId)));
			LOG.debug("actual SSL session Id: " + actualSessionId);
			throw new SecurityException("SSL session Id mismatch");
		}
		LOG.debug("SSL session identifier checked");
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

		String maxMaturity = config
				.getInitParameter(CHALLENGE_MAX_MATURITY_INIT_PARAM_NAME);
		if (null != maxMaturity) {
			this.maxMaturity = Long.parseLong(maxMaturity);
			LOG.debug("explicit max maturity: " + this.maxMaturity);
		} else {
			this.maxMaturity = null;
		}

		String sessionIdChannelBinding = config
				.getInitParameter(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME);
		if (null != sessionIdChannelBinding) {
			this.sessionIdChannelBinding = Boolean
					.parseBoolean(sessionIdChannelBinding);
		}

		String channelBindingServerCertificate = config
				.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVER_CERTIFICATE);
		if (null != channelBindingServerCertificate) {
			File serverCertificateFile = new File(
					channelBindingServerCertificate);
			if (false == serverCertificateFile.exists()) {
				throw new ServletException("server certificate not found: "
						+ serverCertificateFile);
			}
			try {
				this.encodedServerCertificate = FileUtils
						.readFileToByteArray(serverCertificateFile);
			} catch (IOException e) {
				throw new ServletException("error reading server certificate: "
						+ e.getMessage(), e);
			}
		}

		this.nrcidSecret = config
				.getInitParameter(NRCID_SECRET_INIT_PARAM_NAME);
		if (null != this.nrcidSecret) {
			this.nrcidAppId = config
					.getInitParameter(NRCID_APP_ID_INIT_PARAM_NAME);
			this.nrcidOrgId = config
					.getInitParameter(NRCID_ORG_ID_INIT_PARAM_NAME);
		}
	}
}
