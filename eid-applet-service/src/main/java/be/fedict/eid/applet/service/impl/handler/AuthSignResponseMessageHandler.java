/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.impl.AuthenticationSignatureContextImpl;
import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.spi.AuthenticationSignatureContext;
import be.fedict.eid.applet.service.spi.AuthenticationSignatureService;
import be.fedict.eid.applet.shared.AuthSignResponseMessage;
import be.fedict.eid.applet.shared.FinishedMessage;

/**
 * Message handler for authentication signature response messages.
 * 
 * @author Frank Cornelis
 * 
 */
@HandlesMessage(AuthSignResponseMessage.class)
public class AuthSignResponseMessageHandler implements
		MessageHandler<AuthSignResponseMessage> {

	private static final Log LOG = LogFactory
			.getLog(AuthSignResponseMessageHandler.class);

	@InitParam(AuthenticationDataMessageHandler.AUTHN_SIGNATURE_SERVICE_INIT_PARAM_NAME)
	private ServiceLocator<AuthenticationSignatureService> authenticationSignatureServiceLocator;

	public Object handleMessage(AuthSignResponseMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("handleMessage");

		byte[] signatureValue = message.signatureValue;

		AuthenticationSignatureService authenticationSignatureService = this.authenticationSignatureServiceLocator
				.locateService();
		AuthenticationSignatureContext authenticationSignatureContext = new AuthenticationSignatureContextImpl(
				session);
		authenticationSignatureService.postSign(signatureValue, null,
				authenticationSignatureContext);

		FinishedMessage finishedMessage = new FinishedMessage();
		return finishedMessage;
	}

	public void init(ServletConfig config) throws ServletException {
		LOG.debug("init");
	}
}
