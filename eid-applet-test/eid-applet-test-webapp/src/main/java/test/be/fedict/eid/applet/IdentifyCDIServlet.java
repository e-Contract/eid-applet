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

package test.be.fedict.eid.applet;

import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.servlet.annotation.WebServlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.e_contract.eid.applet.service.AppletServiceCDIServlet;
import be.fedict.eid.applet.service.cdi.AuthenticatedEvent;
import be.fedict.eid.applet.service.cdi.AuthenticationEvent;
import be.fedict.eid.applet.service.cdi.BeIDContext;
import be.fedict.eid.applet.service.cdi.IdentityEvent;
import be.fedict.eid.applet.service.cdi.StartEvent;

@WebServlet(IdentifyCDIServlet.CONTEXT)
public class IdentifyCDIServlet extends AppletServiceCDIServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(IdentifyCDIServlet.class);

	public static final String CONTEXT = "/applet-service-cdi";

	@Inject
	private Controller controller;

	public void handleStart(
			@Observes @BeIDContext(CONTEXT) StartEvent startEvent) {
		LOG.debug("start event");
		switch (this.controller.getOperation()) {
		case IDENTIFICATION:
			startEvent.performIdentification().includeAddress();
			break;
		case AUTHENTICATION:
			startEvent.performAuthentication().includeIdentity();
			break;
		}
	}

	public void handleReset(
			@Observes @BeIDContext(CONTEXT) StartEvent startEvent) {
		this.controller.reset();
	}

	public void handleIdentity(
			@Observes @BeIDContext(CONTEXT) IdentityEvent identityEvent) {
		LOG.debug("handle identity");
		LOG.debug("hello: " + identityEvent.getIdentity().getFirstName());
		this.controller.setIdentity(identityEvent.getIdentity());
	}

	public void handleAuthCertValidation(
			@Observes @BeIDContext(CONTEXT) AuthenticationEvent authenticationEvent) {
		authenticationEvent.valid();
	}

	public void handleAuthenticatedUser(
			@Observes @BeIDContext(CONTEXT) AuthenticatedEvent authenticatedEvent) {
		this.controller.setUserIdentifier(authenticatedEvent
				.getUserIdentifier());
	}
}
