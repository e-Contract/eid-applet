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
import be.fedict.eid.applet.service.cdi.StartEvent;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.shared.HelloMessage;
import be.fedict.eid.applet.shared.IdentificationRequestMessage;

@Handles(HelloMessage.class)
public class HelloMessageHandler implements MessageHandler<HelloMessage> {

	private static final Log LOG = LogFactory.getLog(HelloMessageHandler.class);

	@Inject
	private Event<StartEvent> startEvent;

	@Override
	public Object handleMessage(HelloMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("hello message handler");
		StartEvent startEvent = new StartEvent();
		BeIDContextQualifier contextQualifier = new BeIDContextQualifier(
				request);
		this.startEvent.select(contextQualifier).fire(startEvent);
		StartEvent.IdentificationRequest identificationRequest = startEvent
				.getIdentificationRequest();
		if (null != identificationRequest) {
			boolean includeAddress = identificationRequest.isIncludeAddress();
			boolean includePhoto = identificationRequest.isIncludePhoto();
			boolean includeCertificates = identificationRequest
					.isIncludeCertificates();
			boolean removeCard = identificationRequest.isRemoveCard();
			String identityDataUsage = identificationRequest
					.getIdentityDataUsage();
			return new IdentificationRequestMessage(includeAddress,
					includePhoto, true, includeCertificates, removeCard,
					identityDataUsage);
		}
		throw new RuntimeException("no eID action defined for context: "
				+ contextQualifier.getContext());
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
	}
}
