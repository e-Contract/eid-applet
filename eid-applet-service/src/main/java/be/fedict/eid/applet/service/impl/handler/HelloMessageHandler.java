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
import be.fedict.eid.applet.service.spi.SecureClientEnvironmentService;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.AdministrationMessage;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.CheckClientMessage;
import be.fedict.eid.applet.shared.DiagnosticMessage;
import be.fedict.eid.applet.shared.FilesDigestRequestMessage;
import be.fedict.eid.applet.shared.HelloMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.KioskMessage;
import be.fedict.eid.applet.shared.SignCertificatesRequestMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

/**
 * Message handler for hello message.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(HelloMessage.class)
public class HelloMessageHandler implements MessageHandler<HelloMessage> {

	private static final Log LOG = LogFactory.getLog(HelloMessageHandler.class);

	public static final String INCLUDE_IDENTITY_INIT_PARAM_NAME = "IncludeIdentity";

	public static final String INCLUDE_PHOTO_INIT_PARAM_NAME = "IncludePhoto";

	public static final String INCLUDE_CERTS_INIT_PARAM_NAME = "IncludeCertificates";

	public static final String INCLUDE_ADDRESS_INIT_PARAM_NAME = "IncludeAddress";

	public static final String SECURE_CLIENT_ENV_SERVICE_INIT_PARAM_NAME = "SecureClientEnvironmentService";

	public static final String IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME = "IdentityIntegrityService";

	public static final String SIGNATURE_SERVICE_INIT_PARAM_NAME = "SignatureService";

	public static final String PRIVACY_SERVICE_INIT_PARAM_NAME = "PrivacyService";

	public static final String REMOVE_CARD_INIT_PARAM_NAME = "RemoveCard";

	public static final String HOSTNAME_INIT_PARAM_NAME = "Hostname";

	public static final String INET_ADDRESS_INIT_PARAM_NAME = "InetAddress";

	public static final String CHANGE_PIN_INIT_PARAM_NAME = "ChangePin";

	public static final String UNBLOCK_PIN_INIT_PARAM_NAME = "UnblockPin";

	public static final String LOGOFF_INIT_PARAM_NAME = "Logoff";

	public static final String PRE_LOGOFF_INIT_PARAM_NAME = "PreLogoff";

	public static final String KIOSK_INIT_PARAM_NAME = "Kiosk";

	public static final String SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME = "SessionIdChannelBinding";

	public static final String CHANNEL_BINDING_SERVER_CERTIFICATE = "ChannelBindingServerCertificate";

	public static final String CHANNEL_BINDING_SERVICE = "ChannelBindingService";

	public static final String REQUIRE_SECURE_READER_INIT_PARAM_NAME = "RequireSecureReader";

	public static final String DIAGNOSTIC_MODE_INIT_PARAM_NAME = "DiagnosticMode";

	private boolean includePhoto;

	private boolean includeAddress;

	private boolean includeIdentity;

	private boolean removeCard;

	private boolean includeHostname;

	private boolean includeInetAddress;

	private boolean changePin;

	private boolean unblockPin;

	private boolean logoff;

	private boolean preLogoff;

	private boolean includeCertificates;

	private boolean kiosk;

	private boolean sessionIdChannelBinding;

	private boolean serverCertificateChannelBinding;

	private boolean requireSecureReader;

	private boolean diagnosticMode;

	private ServiceLocator<SecureClientEnvironmentService> secureClientEnvServiceLocator;

	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	private ServiceLocator<SignatureService> signatureServiceLocator;

	private ServiceLocator<PrivacyService> privacyServiceLocator;

	public Object handleMessage(HelloMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("hello message received");

		storeClientLanguage(message.language, session);

		if (this.diagnosticMode) {
			LOG.debug("diagnostic mode");
			DiagnosticMessage diagnosticMessage = new DiagnosticMessage();
			return diagnosticMessage;
		}

		SecureClientEnvironmentService secureClientEnvService = this.secureClientEnvServiceLocator
				.locateService();
		if (null != secureClientEnvService) {
			CheckClientMessage checkClientMessage = new CheckClientMessage();
			return checkClientMessage;
		}
		if (this.kiosk) {
			LOG.debug("operating in Kiosk Mode");
			KioskMessage kioskMessage = new KioskMessage();
			return kioskMessage;
		}
		if (this.changePin || this.unblockPin) {
			AdministrationMessage administrationMessage = new AdministrationMessage(
					this.changePin, this.unblockPin, this.logoff,
					this.removeCard, this.requireSecureReader);
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
			if (true == this.includeCertificates) {
				LOG.debug("include signing certificate chain during pre-sign");
				SignCertificatesRequestMessage signCertificatesRequestMessage = new SignCertificatesRequestMessage();
				return signCertificatesRequestMessage;
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
		}

		IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
				.locateService();
		boolean includeIntegrityData = null != identityIntegrityService;
		PrivacyService privacyService = this.privacyServiceLocator
				.locateService();
		String identityDataUsage;
		if (null != privacyService) {
			identityDataUsage = privacyService
					.getIdentityDataUsage(message.language);
		} else {
			identityDataUsage = null;
		}
		IdentificationRequestMessage responseMessage = new IdentificationRequestMessage(
				this.includeAddress, this.includePhoto, includeIntegrityData,
				this.includeCertificates, this.removeCard, identityDataUsage);
		return responseMessage;
	}

	private static final String CLIENT_LANGUAGE_SESSION_ATTRIBUTE = HelloMessageHandler.class
			.getName()
			+ ".clientLanguage";

	private void storeClientLanguage(String language, HttpSession httpSession) {
		httpSession.setAttribute(CLIENT_LANGUAGE_SESSION_ATTRIBUTE, language);
	}

	public static String getClientLanguage(HttpSession httpSession) {
		String clientLanguage = (String) httpSession
				.getAttribute(CLIENT_LANGUAGE_SESSION_ATTRIBUTE);
		return clientLanguage;
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
		String includeIdentity = config
				.getInitParameter(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME);
		if (null != includeIdentity) {
			this.includeIdentity = Boolean.parseBoolean(includeIdentity);
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
		this.privacyServiceLocator = new ServiceLocator<PrivacyService>(
				PRIVACY_SERVICE_INIT_PARAM_NAME, config);

		String removeCard = config
				.getInitParameter(REMOVE_CARD_INIT_PARAM_NAME);
		if (null != removeCard) {
			this.removeCard = Boolean.parseBoolean(removeCard);
		}

		String includeCertificates = config
				.getInitParameter(INCLUDE_CERTS_INIT_PARAM_NAME);
		if (null != includeCertificates) {
			this.includeCertificates = Boolean
					.parseBoolean(includeCertificates);
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

		String preLogoff = config.getInitParameter(PRE_LOGOFF_INIT_PARAM_NAME);
		if (null != preLogoff) {
			this.preLogoff = Boolean.parseBoolean(preLogoff);
		}

		String kiosk = config.getInitParameter(KIOSK_INIT_PARAM_NAME);
		if (null != kiosk) {
			this.kiosk = Boolean.parseBoolean(kiosk);
		}

		String diagnosticMode = config
				.getInitParameter(DIAGNOSTIC_MODE_INIT_PARAM_NAME);
		if (null != diagnosticMode) {
			this.diagnosticMode = Boolean.parseBoolean(diagnosticMode);
		}

		String requireSecureReader = config
				.getInitParameter(REQUIRE_SECURE_READER_INIT_PARAM_NAME);
		if (null != requireSecureReader) {
			this.requireSecureReader = Boolean
					.parseBoolean(requireSecureReader);
		}

		String sessionIdChannelBinding = config
				.getInitParameter(SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME);
		if (null != sessionIdChannelBinding) {
			this.sessionIdChannelBinding = Boolean
					.parseBoolean(sessionIdChannelBinding);
		}

		String channelBindingServerCertificate = config
				.getInitParameter(CHANNEL_BINDING_SERVER_CERTIFICATE);
		if (null != channelBindingServerCertificate) {
			this.serverCertificateChannelBinding = true;
		}
		String channelBindingService = config
				.getInitParameter(CHANNEL_BINDING_SERVICE);
		if (null != channelBindingService) {
			this.serverCertificateChannelBinding = true;
		}
	}
}
