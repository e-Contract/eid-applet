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
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.IdentityEvent;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;
import be.fedict.eid.applet.shared.FinishedMessage;
import be.fedict.eid.applet.shared.IdentityDataMessage;

@Handles(IdentityDataMessage.class)
public class IdentityDataMessageHandler implements
		MessageHandler<IdentityDataMessage> {

	private static final Log LOG = LogFactory
			.getLog(IdentityDataMessageHandler.class);

	@Inject
	private Event<IdentityEvent> identityEvent;

	@Override
	public Object handleMessage(IdentityDataMessage message,
			Map<String, String> httpHeaders, HttpServletRequest request,
			HttpSession session) throws ServletException {
		LOG.debug("handle identity");
		Identity identity = TlvParser.parse(message.idFile, Identity.class);
		BeIDContextQualifier contextQualifier = new BeIDContextQualifier(
				request);
		this.identityEvent.select(contextQualifier).fire(
				new IdentityEvent(identity));
		return new FinishedMessage();
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
	}
}
