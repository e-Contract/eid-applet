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

package be.e_contract.eid.applet.service;

import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.e_contract.eid.applet.service.impl.HandlesQualifier;
import be.fedict.eid.applet.service.AbstractAppletServiceServlet;
import be.fedict.eid.applet.service.impl.handler.MessageHandler;
import be.fedict.eid.applet.shared.AbstractProtocolMessage;

public class AppletServiceCDIServlet extends AbstractAppletServiceServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AppletServiceCDIServlet.class);

	@Inject
	@Any
	private Instance<MessageHandler<?>> messageHandlers;

	@Override
	protected <T> MessageHandler<T> getMessageHandler(Class<T> messageClass) {
		LOG.debug("get message handler: " + messageClass.getName());
		return (MessageHandler<T>) this.messageHandlers
				.select(new HandlesQualifier(
						(Class<? extends AbstractProtocolMessage>) messageClass))
				.get();
	}

}
