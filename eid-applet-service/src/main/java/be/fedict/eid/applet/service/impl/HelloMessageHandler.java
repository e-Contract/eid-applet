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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.applet.service.spi.SecureClientEnvironmentService;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.AdministrationMessage;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.CheckClientMessage;
import be.fedict.eid.applet.shared.FilesDigestRequestMessage;
import be.fedict.eid.applet.shared.HelloMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

/**
 * Message handler for hello message.
 * 
 * @author fcorneli
 * 
 */
public class HelloMessageHandler implements MessageHandler<HelloMessage> {

	private static final Log LOG = LogFactory.getLog(HelloMessageHandler.class);

	public static final String INCLUDE_PHOTO_INIT_PARAM_NAME = "IncludePhoto";

	public static final String INCLUDE_ADDRESS_INIT_PARAM_NAME = "IncludeAddress";

	public static final String SECURE_CLIENT_ENV_SERVICE_INIT_PARAM_NAME = "SecureClientEnvironmentService";

	public static final String IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME = "IdentityIntegrityService";

	public static final String SIGNATURE_SERVICE_INIT_PARAM_NAME = "SignatureService";

	public static final String REMOVE_CARD_INIT_PARAM_NAME = "RemoveCard";

	public static final String HOSTNAME_INIT_PARAM_NAME = "Hostname";

	public static final String INET_ADDRESS_INIT_PARAM_NAME = "InetAddress";

	public static final String CHANGE_PIN_INIT_PARAM_NAME = "ChangePin";

	public static final String UNBLOCK_PIN_INIT_PARAM_NAME = "UnblockPin";

	public static final String LOGOFF_INIT_PARAM_NAME = "Logoff";

	private boolean includePhoto;

	private boolean includeAddress;

	private boolean removeCard;

	private boolean includeHostname;

	private boolean includeInetAddress;

	private boolean changePin;

	private boolean unblockPin;

	private boolean logoff;

	private ServiceLocator<SecureClientEnvironmentService> secureClientEnvServiceLocator;

	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	private ServiceLocator<SignatureService> signatureServiceLocator;

	private SecureRandom secureRandom;

	public static final String DIGEST_VALUE_SESSION_ATTRIBUTE = HelloMessageHandler.class
			.getName()
			+ ".digestValue";

	public static void setDigestValue(byte[] digestValue, HttpSession session) {
		session.setAttribute(DIGEST_VALUE_SESSION_ATTRIBUTE, digestValue);
	}

	public static byte[] getDigestValue(HttpSession session) {
		return (byte[]) session.getAttribute(DIGEST_VALUE_SESSION_ATTRIBUTE);
	}

	public Object handleMessage(HelloMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("hello message received");

		SecureClientEnvironmentService secureClientEnvService = this.secureClientEnvServiceLocator
				.locateService();
		if (null != secureClientEnvService) {
			CheckClientMessage checkClientMessage = new CheckClientMessage();
			return checkClientMessage;
		}
		if (this.changePin || this.unblockPin) {
			AdministrationMessage administrationMessage = new AdministrationMessage(
					this.changePin, this.unblockPin, this.logoff,
					this.removeCard);
			return administrationMessage;
		}
		SignatureService signatureService = this.signatureServiceLocator
				.locateService();
		if (null != signatureService) {
			String filesDigestAlgo = signatureService.getFilesDigestAlgorithm();
			if (null != filesDigestAlgo) {
				LOG.debug("files digest algo: " + filesDigestAlgo);
				FilesDigestRequestMessage filesDigestRequestMessage = new FilesDigestRequestMessage();
				filesDigestRequestMessage.digestAlgo = filesDigestAlgo;
				return filesDigestRequestMessage;
			}

			DigestInfo digestInfo;
			try {
				digestInfo = signatureService.preSign(null, null);
			} catch (NoSuchAlgorithmException e) {
				throw new ServletException("no such algo: " + e.getMessage(), e);
			}

			// also save it in the session for later verification
			setDigestValue(digestInfo.digestValue, session);

			SignRequestMessage signRequestMessage = new SignRequestMessage(
					digestInfo.digestValue, digestInfo.digestAlgo,
					digestInfo.description, this.logoff, this.removeCard);
			return signRequestMessage;
		}
		AuthenticationService authenticationService = this.authenticationServiceLocator
				.locateService();
		if (null != authenticationService) {
			// since SHA-1 is 20 bytes we also take 20 here.
			byte[] challenge = new byte[20];
			this.secureRandom.nextBytes(challenge);
			// also keep the challenge in the session (server side!)
			AuthenticationDataMessageHandler.setAuthnChallenge(challenge,
					session);
			AuthenticationRequestMessage authenticationRequestMessage = new AuthenticationRequestMessage(
					challenge, this.includeHostname, this.includeInetAddress,
					this.logoff, this.removeCard);
			return authenticationRequestMessage;
		}

		IdentificationRequestMessage responseMessage = new IdentificationRequestMessage();
		responseMessage.includePhoto = this.includePhoto;
		responseMessage.includeAddress = this.includeAddress;
		responseMessage.removeCard = this.removeCard;
		IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
				.locateService();
		if (null != identityIntegrityService) {
			responseMessage.includeIntegrityData = true;
		}
		return responseMessage;
	}

	public void init(ServletConfig config) throws ServletException {
		String includeAddress = config
				.getInitParameter(INCLUDE_ADDRESS_INIT_PARAM_NAME);
		if (null != includeAddress) {
			this.includeAddress = Boolean.parseBoolean(includeAddress);
		}
		String includePhoto = config
				.getInitParameter(INCLUDE_PHOTO_INIT_PARAM_NAME);
		if (null != includePhoto) {
			this.includePhoto = Boolean.parseBoolean(includePhoto);
		}
		this.secureClientEnvServiceLocator = new ServiceLocator<SecureClientEnvironmentService>(
				SECURE_CLIENT_ENV_SERVICE_INIT_PARAM_NAME, config);
		this.identityIntegrityServiceLocator = new ServiceLocator<IdentityIntegrityService>(
				IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME, config);
		this.authenticationServiceLocator = new ServiceLocator<AuthenticationService>(
				AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME,
				config);
		this.signatureServiceLocator = new ServiceLocator<SignatureService>(
				SIGNATURE_SERVICE_INIT_PARAM_NAME, config);

		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());

		String removeCard = config
				.getInitParameter(REMOVE_CARD_INIT_PARAM_NAME);
		if (null != removeCard) {
			this.removeCard = Boolean.parseBoolean(removeCard);
		}

		String hostname = config.getInitParameter(HOSTNAME_INIT_PARAM_NAME);
		if (null != hostname) {
			this.includeHostname = true;
		}

		String inetAddress = config
				.getInitParameter(INET_ADDRESS_INIT_PARAM_NAME);
		if (null != inetAddress) {
			this.includeInetAddress = true;
		}

		String changePin = config.getInitParameter(CHANGE_PIN_INIT_PARAM_NAME);
		if (null != changePin) {
			this.changePin = Boolean.parseBoolean(changePin);
		}

		String unblockPin = config
				.getInitParameter(UNBLOCK_PIN_INIT_PARAM_NAME);
		if (null != unblockPin) {
			this.unblockPin = Boolean.parseBoolean(unblockPin);
		}

		String logoff = config.getInitParameter(LOGOFF_INIT_PARAM_NAME);
		if (null != logoff) {
			this.logoff = Boolean.parseBoolean(logoff);
		}
	}
}
