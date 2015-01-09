/*
 * eID Applet Project.
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

package be.e_contract.eid.applet.service.impl.handler;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.enterprise.event.Event;
import javax.inject.Inject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import be.e_contract.eid.applet.service.impl.BeIDContextQualifier;
import be.e_contract.eid.applet.service.impl.Handles;
import be.fedict.eid.applet.service.cdi.AuthenticatedEvent;
import be.fedict.eid.applet.service.cdi.AuthenticationEvent;
import be.fedict.eid.applet.service.impl.AuthenticationChallenge;
import be.fedict.eid.applet.service.impl.UserIdentifierUtil;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.shared.AuthenticationContract;
import be.fedict.eid.applet.shared.AuthenticationDataMessage;
import be.fedict.eid.applet.shared.FinishedMessage;

@Handles(AuthenticationDataMessage.class)
public class AuthenticationDataMessageHandler implements
		MessageHandler<AuthenticationDataMessage> {

	@Inject
	private Event<AuthenticationEvent> authenticationEvent;

	@Inject
	private Event<AuthenticatedEvent> authenticatedEvent;

	@Override
	public Object handleMessage(AuthenticationDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		byte[] challenge;
		try {
			challenge = AuthenticationChallenge.getAuthnChallenge(session);
		} catch (SecurityException e) {
			throw new ServletException("security error: " + e.getMessage(), e);
		}
		/*
		 * We validate the authentication contract using the client-side
		 * communicated server SSL certificate in case of secure channel
		 * binding.
		 */
		AuthenticationContract authenticationContract = new AuthenticationContract(
				message.saltValue, null, null, message.sessionId, null,
				challenge);
		byte[] toBeSigned;
		try {
			toBeSigned = authenticationContract.calculateToBeSigned();
		} catch (IOException e) {
			throw new ServletException("IO error: " + e.getMessage(), e);
		}

		PublicKey signingKey = message.authnCert.getPublicKey();
		byte[] signatureValue = message.signatureValue;
		try {
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(signingKey);
			signature.update(toBeSigned);
			boolean result = signature.verify(signatureValue);
			if (false == result) {
				throw new SecurityException("authn signature incorrect");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new SecurityException("algo error");
		} catch (InvalidKeyException e) {
			throw new SecurityException("authn key error");
		} catch (SignatureException e) {
			throw new SecurityException("signature error");
		}

		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		certificateChain.add(message.authnCert);
		certificateChain.add(message.citizenCaCert);
		certificateChain.add(message.rootCaCert);

		AuthenticationEvent authenticationEvent = new AuthenticationEvent(
				certificateChain);
		BeIDContextQualifier contextQualifier = new BeIDContextQualifier(
				request);
		this.authenticationEvent.select(contextQualifier).fire(
				authenticationEvent);
		if (false == authenticationEvent.isValid()) {
			throw new SecurityException(
					"invalid authentication certificate chain");
		}

		String userId = UserIdentifierUtil.getUserId(message.authnCert);
		AuthenticatedEvent authenticatedEvent = new AuthenticatedEvent(userId);
		this.authenticatedEvent.select(contextQualifier).fire(
				authenticatedEvent);

		return new FinishedMessage();
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
	}
}
