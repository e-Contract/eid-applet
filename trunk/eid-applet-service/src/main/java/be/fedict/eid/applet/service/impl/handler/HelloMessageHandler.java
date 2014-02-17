/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 * Copyright (C) 2009 Frank Cornelis.
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
import be.fedict.eid.applet.service.impl.RequestContext;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.applet.service.spi.IdentityRequest;
import be.fedict.eid.applet.service.spi.IdentityService;
import be.fedict.eid.applet.service.spi.PrivacyService;
import be.fedict.eid.applet.service.spi.SecureCardReaderService;
import be.fedict.eid.applet.service.spi.SecureClientEnvironmentService;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.AdministrationMessage;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.CheckClientMessage;
import be.fedict.eid.applet.shared.FilesDigestRequestMessage;
import be.fedict.eid.applet.shared.HelloMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
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

	public static final String SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME = "SessionIdChannelBinding";

	public static final String CHANNEL_BINDING_SERVER_CERTIFICATE = "ChannelBindingServerCertificate";

	public static final String CHANNEL_BINDING_SERVICE = "ChannelBindingService";

	public static final String REQUIRE_SECURE_READER_INIT_PARAM_NAME = "RequireSecureReader";

	public static final String IDENTITY_SERVICE_INIT_PARAM_NAME = "IdentityService";

	public static final String SECURE_CARD_READER_SERVICE_INIT_PARAM_NAME = "SecureCardReaderService";

	@InitParam(INCLUDE_PHOTO_INIT_PARAM_NAME)
	private boolean includePhoto;

	@InitParam(INCLUDE_ADDRESS_INIT_PARAM_NAME)
	private boolean includeAddress;

	@InitParam(INCLUDE_IDENTITY_INIT_PARAM_NAME)
	private boolean includeIdentity;

	@InitParam(REMOVE_CARD_INIT_PARAM_NAME)
	private boolean removeCard;

	private boolean includeHostname;

	private boolean includeInetAddress;

	@InitParam(CHANGE_PIN_INIT_PARAM_NAME)
	private boolean changePin;

	@InitParam(UNBLOCK_PIN_INIT_PARAM_NAME)
	private boolean unblockPin;

	@InitParam(LOGOFF_INIT_PARAM_NAME)
	private boolean logoff;

	@InitParam(PRE_LOGOFF_INIT_PARAM_NAME)
	private boolean preLogoff;

	@InitParam(INCLUDE_CERTS_INIT_PARAM_NAME)
	private boolean includeCertificates;

	@InitParam(SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME)
	private boolean sessionIdChannelBinding;

	private boolean serverCertificateChannelBinding;

	@InitParam(REQUIRE_SECURE_READER_INIT_PARAM_NAME)
	private boolean requireSecureReader;

	@InitParam(SECURE_CLIENT_ENV_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SecureClientEnvironmentService> secureClientEnvServiceLocator;

	@InitParam(IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	@InitParam(SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(PRIVACY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<PrivacyService> privacyServiceLocator;

	@InitParam(IDENTITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityService> identityServiceLocator;

	@InitParam(SECURE_CARD_READER_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SecureCardReaderService> secureCardReaderServiceLocator;

	public Object handleMessage(HelloMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("hello message received");

		storeClientLanguage(message.language, session);

		SecureClientEnvironmentService secureClientEnvService = this.secureClientEnvServiceLocator
				.locateService();
		if (null != secureClientEnvService) {
			CheckClientMessage checkClientMessage = new CheckClientMessage();
			return checkClientMessage;
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
				IdentityIntegrityService identityIntegrityService = this.identityIntegrityServiceLocator
						.locateService();
				boolean includeIntegrityData = null != identityIntegrityService;
				IdentityService identityService = this.identityServiceLocator
						.locateService();
				boolean includeIdentity;
				boolean includeAddress;
				boolean includePhoto;
				if (null != identityService) {
					IdentityRequest identityRequest = identityService
							.getIdentityRequest();
					includeIdentity = identityRequest.includeIdentity();
					includeAddress = identityRequest.includeAddress();
					includePhoto = identityRequest.includePhoto();
				} else {
					includeIdentity = this.includeIdentity;
					includeAddress = this.includeAddress;
					includePhoto = this.includePhoto;
				}
				RequestContext requestContext = new RequestContext(session);
				requestContext.setIncludeIdentity(includeIdentity);
				requestContext.setIncludeAddress(includeAddress);
				requestContext.setIncludePhoto(includePhoto);
				SignCertificatesRequestMessage signCertificatesRequestMessage = new SignCertificatesRequestMessage(
						includeIdentity, includeAddress, includePhoto,
						includeIntegrityData);
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
					digestInfo.digestAlgo, session);

			IdentityService identityService = this.identityServiceLocator
					.locateService();
			boolean removeCard;
			if (null != identityService) {
				IdentityRequest identityRequest = identityService
						.getIdentityRequest();
				removeCard = identityRequest.removeCard();
			} else {
				removeCard = this.removeCard;
			}

			SignRequestMessage signRequestMessage = new SignRequestMessage(
					digestInfo.digestValue, digestInfo.digestAlgo,
					digestInfo.description, this.logoff, removeCard,
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
			boolean includeIdentity;
			boolean includeAddress;
			boolean includePhoto;
			boolean includeCertificates;
			boolean removeCard;
			IdentityService identityService = this.identityServiceLocator
					.locateService();
			if (null != identityService) {
				IdentityRequest identityRequest = identityService
						.getIdentityRequest();
				includeIdentity = identityRequest.includeIdentity();
				includeAddress = identityRequest.includeAddress();
				includePhoto = identityRequest.includePhoto();
				includeCertificates = identityRequest.includeCertificates();
				removeCard = identityRequest.removeCard();
			} else {
				includeIdentity = this.includeIdentity;
				includeAddress = this.includeAddress;
				includePhoto = this.includePhoto;
				includeCertificates = this.includeCertificates;
				removeCard = this.removeCard;
			}
			RequestContext requestContext = new RequestContext(session);
			requestContext.setIncludeIdentity(includeIdentity);
			requestContext.setIncludeAddress(includeAddress);
			requestContext.setIncludePhoto(includePhoto);
			requestContext.setIncludeCertificates(includeCertificates);

			String transactionMessage = null;
			SecureCardReaderService secureCardReaderService = this.secureCardReaderServiceLocator
					.locateService();
			if (null != secureCardReaderService) {
				transactionMessage = secureCardReaderService
						.getTransactionMessage();
				if (null != transactionMessage
						&& transactionMessage.length() > SecureCardReaderService.TRANSACTION_MESSAGE_MAX_SIZE) {
					transactionMessage = transactionMessage
							.substring(
									0,
									SecureCardReaderService.TRANSACTION_MESSAGE_MAX_SIZE);
				}
				LOG.debug("transaction message: " + transactionMessage);
			}
			requestContext.setTransactionMessage(transactionMessage);

			AuthenticationRequestMessage authenticationRequestMessage = new AuthenticationRequestMessage(
					challenge, this.includeHostname, this.includeInetAddress,
					this.logoff, this.preLogoff, removeCard,
					this.sessionIdChannelBinding,
					this.serverCertificateChannelBinding, includeIdentity,
					includeCertificates, includeAddress, includePhoto,
					includeIntegrityData, this.requireSecureReader,
					transactionMessage);
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
		boolean includeAddress;
		boolean includePhoto;
		boolean includeCertificates;
		boolean removeCard;
		IdentityService identityService = this.identityServiceLocator
				.locateService();
		if (null != identityService) {
			IdentityRequest identityRequest = identityService
					.getIdentityRequest();
			includeAddress = identityRequest.includeAddress();
			includePhoto = identityRequest.includePhoto();
			includeCertificates = identityRequest.includeCertificates();
			removeCard = identityRequest.removeCard();
		} else {
			includeAddress = this.includeAddress;
			includePhoto = this.includePhoto;
			includeCertificates = this.includeCertificates;
			removeCard = this.removeCard;
		}
		RequestContext requestContext = new RequestContext(session);
		requestContext.setIncludeAddress(includeAddress);
		requestContext.setIncludePhoto(includePhoto);
		requestContext.setIncludeCertificates(includeCertificates);
		IdentificationRequestMessage responseMessage = new IdentificationRequestMessage(
				includeAddress, includePhoto, includeIntegrityData,
				includeCertificates, removeCard, identityDataUsage);
		return responseMessage;
	}

	private static final String CLIENT_LANGUAGE_SESSION_ATTRIBUTE = HelloMessageHandler.class
			.getName() + ".clientLanguage";

	private void storeClientLanguage(String language, HttpSession httpSession) {
		httpSession.setAttribute(CLIENT_LANGUAGE_SESSION_ATTRIBUTE, language);
	}

	public static String getClientLanguage(HttpSession httpSession) {
		String clientLanguage = (String) httpSession
				.getAttribute(CLIENT_LANGUAGE_SESSION_ATTRIBUTE);
		return clientLanguage;
	}

	public void init(ServletConfig config) throws ServletException {
		String hostname = config.getInitParameter(HOSTNAME_INIT_PARAM_NAME);
		if (null != hostname) {
			this.includeHostname = true;
		}

		String inetAddress = config
				.getInitParameter(INET_ADDRESS_INIT_PARAM_NAME);
		if (null != inetAddress) {
			this.includeInetAddress = true;
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
