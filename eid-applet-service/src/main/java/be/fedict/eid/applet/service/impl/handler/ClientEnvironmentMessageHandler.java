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
import be.fedict.eid.applet.service.impl.RequestContext;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.spi.AuthenticationService;
import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.applet.service.spi.IdentityRequest;
import be.fedict.eid.applet.service.spi.IdentityService;
import be.fedict.eid.applet.service.spi.InsecureClientEnvironmentException;
import be.fedict.eid.applet.service.spi.PrivacyService;
import be.fedict.eid.applet.service.spi.SecureCardReaderService;
import be.fedict.eid.applet.service.spi.SecureClientEnvironmentService;
import be.fedict.eid.applet.service.spi.SignatureService;
import be.fedict.eid.applet.shared.AdministrationMessage;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.ClientEnvironmentMessage;
import be.fedict.eid.applet.shared.FilesDigestRequestMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.InsecureClientMessage;
import be.fedict.eid.applet.shared.SignCertificatesRequestMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

/**
 * Handler for client environment message.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(ClientEnvironmentMessage.class)
public class ClientEnvironmentMessageHandler implements
		MessageHandler<ClientEnvironmentMessage> {

	private static final Log LOG = LogFactory
			.getLog(ClientEnvironmentMessageHandler.class);

	@InitParam(HelloMessageHandler.SECURE_CLIENT_ENV_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SecureClientEnvironmentService> secureClientEnvServiceLocator;

	@InitParam(HelloMessageHandler.INCLUDE_PHOTO_INIT_PARAM_NAME)
	private boolean includePhoto;

	@InitParam(HelloMessageHandler.INCLUDE_ADDRESS_INIT_PARAM_NAME)
	private boolean includeAddress;

	@InitParam(HelloMessageHandler.INCLUDE_IDENTITY_INIT_PARAM_NAME)
	private boolean includeIdentity;

	@InitParam(HelloMessageHandler.IDENTITY_INTEGRITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityIntegrityService> identityIntegrityServiceLocator;

	@InitParam(AuthenticationDataMessageHandler.AUTHN_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationService> authenticationServiceLocator;

	@InitParam(HelloMessageHandler.PRIVACY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<PrivacyService> privacyServiceLocator;

	private SecureRandom secureRandom;

	@InitParam(HelloMessageHandler.REMOVE_CARD_INIT_PARAM_NAME)
	private boolean removeCard;

	@InitParam(HelloMessageHandler.CHANGE_PIN_INIT_PARAM_NAME)
	private boolean changePin;

	@InitParam(HelloMessageHandler.UNBLOCK_PIN_INIT_PARAM_NAME)
	private boolean unblockPin;

	private boolean includeHostname;

	private boolean includeInetAddress;

	@InitParam(HelloMessageHandler.LOGOFF_INIT_PARAM_NAME)
	private boolean logoff;

	@InitParam(HelloMessageHandler.PRE_LOGOFF_INIT_PARAM_NAME)
	private boolean preLogoff;

	@InitParam(HelloMessageHandler.INCLUDE_CERTS_INIT_PARAM_NAME)
	private boolean includeCertificates;

	@InitParam(HelloMessageHandler.SESSION_ID_CHANNEL_BINDING_INIT_PARAM_NAME)
	private boolean sessionIdChannelBinding;

	private boolean serverCertificateChannelBinding;

	@InitParam(HelloMessageHandler.REQUIRE_SECURE_READER_INIT_PARAM_NAME)
	private boolean requireSecureReader;

	@InitParam(HelloMessageHandler.SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SignatureService> signatureServiceLocator;

	@InitParam(HelloMessageHandler.IDENTITY_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<IdentityService> identityServiceLocator;

	@InitParam(HelloMessageHandler.SECURE_CARD_READER_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<SecureCardReaderService> secureCardReaderServiceLocator;

	public Object handleMessage(ClientEnvironmentMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		SecureClientEnvironmentService secureClientEnvService = this.secureClientEnvServiceLocator
				.locateService();
		if (null == secureClientEnvService) {
			throw new ServletException(
					"no secure client env service configured");
		}
		String remoteAddress = request.getRemoteAddr();
		Integer sslKeySize = (Integer) request
				.getAttribute("javax.servlet.request.key_size");
		String userAgent = httpHeaders.get("user-agent");
		String sslCipherSuite = (String) request
				.getAttribute("javax.servlet.request.cipher_suite");
		try {
			secureClientEnvService.checkSecureClientEnvironment(
					message.javaVersion, message.javaVendor, message.osName,
					message.osArch, message.osVersion, userAgent,
					message.navigatorAppName, message.navigatorAppVersion,
					message.navigatorUserAgent, remoteAddress, sslKeySize,
					sslCipherSuite, message.readerList);
		} catch (InsecureClientEnvironmentException e) {
			return new InsecureClientMessage(e.isWarnOnly());
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
			// TODO DRY refactor: is a copy-paste from HelloMessageHandler
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
					session);

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
				transactionMessage = secureCardReaderService.getMessage();
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
	}

	public void init(ServletConfig config) throws ServletException {
		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());

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
