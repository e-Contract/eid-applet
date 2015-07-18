/*
 * eID Applet Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

package be.e_contract.eid.applet.service.impl.handler;

import java.io.Serializable;
import java.util.Map;

import javax.enterprise.event.Event;
import javax.inject.Inject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.e_contract.eid.applet.service.impl.BeIDContextQualifier;
import be.e_contract.eid.applet.service.impl.Handles;
import be.fedict.eid.applet.service.cdi.SignatureDigestEvent;
import be.fedict.eid.applet.service.cdi.StartEvent;
import be.fedict.eid.applet.service.impl.AuthenticationChallenge;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.service.spi.AuthorizationException;
import be.fedict.eid.applet.shared.AuthenticationRequestMessage;
import be.fedict.eid.applet.shared.ErrorCode;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.HelloMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;
import be.fedict.eid.applet.shared.SignCertificatesRequestMessage;
import be.fedict.eid.applet.shared.SignRequestMessage;

@Handles(HelloMessage.class)
public class HelloMessageHandler implements MessageHandler<HelloMessage>, Serializable {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(HelloMessageHandler.class);

	@Inject
	private Event<StartEvent> startEvent;

	@Inject
	private Event<SignatureDigestEvent> signatureDigestEvent;

	@Inject
	private SignatureState signatureState;

	@Override
	public Object handleMessage(HelloMessage message, Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("hello message handler");

		StartEvent startEvent = new StartEvent();
		BeIDContextQualifier contextQualifier = new BeIDContextQualifier(request);
		this.startEvent.select(contextQualifier).fire(startEvent);

		StartEvent.IdentificationRequest identificationRequest = startEvent.getIdentificationRequest();
		if (null != identificationRequest) {
			boolean includeAddress = identificationRequest.isIncludeAddress();
			boolean includePhoto = identificationRequest.isIncludePhoto();
			boolean includeCertificates = identificationRequest.isIncludeCertificates();
			boolean removeCard = identificationRequest.isRemoveCard();
			String identityDataUsage = identificationRequest.getIdentityDataUsage();
			return new IdentificationRequestMessage(includeAddress, includePhoto, true, includeCertificates, removeCard,
					identityDataUsage);
		}

		StartEvent.AuthenticationRequest authenticationRequest = startEvent.getAuthenticationRequest();
		if (null != authenticationRequest) {
			boolean includeHostname = false;
			byte[] challenge = AuthenticationChallenge.generateChallenge(session);
			boolean logoff = authenticationRequest.isLogoff();
			boolean removeCard = authenticationRequest.isRemoveCard();
			boolean includeInetAddress = false;
			boolean preLogoff = authenticationRequest.isPreLogoff();
			boolean sessionIdChannelBinding = false;
			boolean serverCertificateChannelBinding = authenticationRequest.isSecureChannelBinding();
			boolean includeCertificates = false;
			boolean includeAddress = authenticationRequest.isIncludeAddress();
			boolean includeIdentity = authenticationRequest.isIncludeIdentity();
			boolean includePhoto = authenticationRequest.isIncludePhoto();
			boolean requireSecureReader = authenticationRequest.isRequireSecureReader();
			boolean includeIntegrityData;
			if (includeIdentity || includeAddress || includePhoto) {
				includeIntegrityData = true;
			} else {
				includeIntegrityData = false;
			}
			String transactionMessage = authenticationRequest.getTransactionMessage();
			return new AuthenticationRequestMessage(challenge, includeHostname, includeInetAddress, logoff, preLogoff,
					removeCard, sessionIdChannelBinding, serverCertificateChannelBinding, includeIdentity,
					includeCertificates, includeAddress, includePhoto, includeIntegrityData, requireSecureReader,
					transactionMessage);
		}

		StartEvent.SigningRequest signingRequest = startEvent.getSigningRequest();
		if (null != signingRequest) {
			boolean includeIdentity = signingRequest.isIncludeIdentity();
			boolean includeAddress = signingRequest.isIncludeAddress();
			boolean includePhoto = signingRequest.isIncludePhoto();
			boolean includeCertificates = signingRequest.isIncludeCertificates();
			if (includeIdentity || includeAddress || includePhoto || includeCertificates) {
				return new SignCertificatesRequestMessage(includeIdentity, includeAddress, includePhoto, true);
			}
			SignatureDigestEvent signatureDigestEvent = new SignatureDigestEvent();
			try {
				this.signatureDigestEvent.select(contextQualifier).fire(signatureDigestEvent);
			} catch (AuthorizationException e) {
				return new FinishedMessage(ErrorCode.AUTHORIZATION);
			}
			String digestAlgo = signatureDigestEvent.getDigestAlgo();
			boolean logoff = signatureDigestEvent.isLogoff();
			boolean requireSecureReader = false;
			boolean removeCard = signatureDigestEvent.isRemoveCard();
			String description = signatureDigestEvent.getDescription();
			byte[] digestValue = signatureDigestEvent.getDigestValue();

			// required for later verification
			this.signatureState.setDigestValue(digestValue);
			this.signatureState.setDigestAlgo(digestAlgo);

			return new SignRequestMessage(digestValue, digestAlgo, description, logoff, removeCard,
					requireSecureReader);
		}

		throw new RuntimeException("no eID action defined for context: " + contextQualifier.getContext());
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
	}
}
