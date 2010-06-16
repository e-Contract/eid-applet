/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 * Copyright (C) 2009 Frank Cornelis.
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
import java.security.SecureRandom;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.impl.AuthenticationChallenge;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.applet.service.spi.PrivacyService;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.AdministrationMessage;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.ContinueInsecureMessage;
import be.fedict.eid.applet.shared.FilesDigestRequestMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

/**
 * Handler for continue insecure message.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(ContinueInsecureMessage.class)
public class ContinueInsecureMessageHandler implements
		MessageHandler<ContinueInsecureMessage> {

	private static final Log LOG = LogFactory
			.getLog(ContinueInsecureMessageHandler.class);

	private boolean includePhoto;

	private boolean includeAddress;

	private boolean includeIdentity;

	private boolean includeInetAddress;

	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	private ServiceLocator<PrivacyService> privacyServiceLocator;

	private SecureRandom secureRandom;

	private boolean removeCard;

	private boolean changePin;

	private boolean unblockPin;

	private boolean includeHostname;

	private boolean logoff;

	private boolean preLogoff;

	private boolean includeCertificates;

	private boolean sessionIdChannelBinding;

	private boolean serverCertificateChannelBinding;

	private boolean requireSecureReader;

	private ServiceLocator<SignatureService> signatureServiceLocator;

	public Object handleMessage(ContinueInsecureMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		if (this.changePin || this.unblockPin) {
			AdministrationMessage administrationMessage = new AdministrationMessage(
					this.changePin, this.unblockPin, this.logoff,
					this.removeCard, this.requireSecureReader);
			return administrationMessage;
		}
		SignatureService signatureService = this.signatureServiceLocator
				.locateService();
		if (null != signatureService) {
			// TODO DRY refactor: is a copy-paste from HelloMessageHandler
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
			SignatureDataMessageHandler.setDigestValue(digestInfo.digestValue,
					session);

			SignRequestMessage signRequestMessage = new SignRequestMessage(
					digestInfo.digestValue, digestInfo.digestAlgo,
					digestInfo.description, this.logoff, this.removeCard,
					this.requireSecureReader);
			return signRequestMessage;
		}
		AuthenticationService authenticationService = this.authenticationServiceLocator
				.locateService();
		if (null != authenticationService) {
			byte[] challenge = AuthenticationChallenge
					.generateChallenge(session);
			IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
					.locateService();
			boolean includeIntegrityData = null != identityIntegrityService;
			AuthenticationRequestMessage authenticationRequestMessage = new AuthenticationRequestMessage(
					challenge, this.includeHostname, this.includeInetAddress,
					this.logoff, this.preLogoff, this.removeCard,
					this.sessionIdChannelBinding,
					this.serverCertificateChannelBinding, this.includeIdentity,
					this.includeCertificates, this.includeAddress,
					this.includePhoto, includeIntegrityData,
					this.requireSecureReader);
			return authenticationRequestMessage;
		} else {
			IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
					.locateService();
			boolean includeIntegrityData = null != identityIntegrityService;
			PrivacyService privacyService = this.privacyServiceLocator
					.locateService();
			String identityDataUsage;
			if (null != privacyService) {
				String clientLanguage = HelloMessageHandler
						.getClientLanguage(session);
				identityDataUsage = privacyService
						.getIdentityDataUsage(clientLanguage);
			} else {
				identityDataUsage = null;
			}
			IdentificationRequestMessage responseMessage = new IdentificationRequestMessage(
					this.includeAddress, this.includePhoto,
					includeIntegrityData, this.includeCertificates,
					this.removeCard, identityDataUsage);
			return responseMessage;
		}
	}

	public void init(ServletConfig config) throws ServletException {
		String includeAddress = config
				.getInitParameter(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME);
		if (null != includeAddress) {
			this.includeAddress = Boolean.parseBoolean(includeAddress);
		}
		String includePhoto = config
				.getInitParameter(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME);
		if (null != includePhoto) {
			this.includePhoto = Boolean.parseBoolean(includePhoto);
		}
		String includeIdentity = config
				.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME);
		if (null != includeIdentity) {
			this.includeIdentity = Boolean.parseBoolean(includeIdentity);
		}
		this.identityIntegrityServiceLocator = new ServiceLocator<IdentityIntegrityService>(
				HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME,
				config);
		this.authenticationServiceLocator = new ServiceLocator<AuthenticationService>(
				AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME,
				config);
		this.signatureServiceLocator = new ServiceLocator<SignatureService>(
				HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME, config);
		this.privacyServiceLocator = new ServiceLocator<PrivacyService>(
				HelloMessageHandler.PRIVACY_SERVICE_INIT_PARAM_NAME, config);

		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());

		String removeCard = config
				.getInitParameter(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME);
		if (null != removeCard) {
			this.removeCard = Boolean.parseBoolean(removeCard);
		}

		String includeCertificates = config
				.getInitParameter(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME);
		if (null != includeCertificates) {
			this.includeCertificates = Boolean
					.parseBoolean(includeCertificates);
		}

		String hostname = config
				.getInitParameter(HelloMessageHandler.HOSTNAME_INIT_PARAM_NAME);
		if (null != hostname) {
			this.includeHostname = true;
		}

		String inetAddress = config
				.getInitParameter(HelloMessageHandler.INET_ADDRESS_INIT_PARAM_NAME);
		if (null != inetAddress) {
			this.includeInetAddress = true;
		}

		String changePin = config
				.getInitParameter(HelloMessageHandler.CHANGE_PIN_INIT_PARAM_NAME);
		if (null != changePin) {
			this.changePin = Boolean.parseBoolean(changePin);
		}

		String unblockPin = config
				.getInitParameter(HelloMessageHandler.UNBLOCK_PIN_INIT_PARAM_NAME);
		if (null != unblockPin) {
			this.unblockPin = Boolean.parseBoolean(unblockPin);
		}

		String logoff = config
				.getInitParameter(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME);
		if (null != logoff) {
			this.logoff = Boolean.parseBoolean(logoff);
		}

		String preLogoff = config
				.getInitParameter(HelloMessageHandler.PRE_LOGOFF_INIT_PARAM_NAME);
		if (null != preLogoff) {
			this.preLogoff = Boolean.parseBoolean(preLogoff);
		}

		String requireSecureReader = config
				.getInitParameter(HelloMessageHandler.REQUIRE_SECURE_READER_INIT_PARAM_NAME);
		if (null != requireSecureReader) {
			this.requireSecureReader = Boolean
					.parseBoolean(requireSecureReader);
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
			this.serverCertificateChannelBinding = true;
		}
		String channelBindingService = config
				.getInitParameter(HelloMessageHandler.CHANNEL_BINDING_SERVICE);
		if (null != channelBindingService) {
			this.serverCertificateChannelBinding = true;
		}
	}
}
