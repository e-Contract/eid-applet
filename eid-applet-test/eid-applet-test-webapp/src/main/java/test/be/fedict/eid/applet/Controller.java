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

package test.be.fedict.eid.applet;

import java.io.IOException;
import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Named;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.cdi.AuthenticatedEvent;
import be.fedict.eid.applet.service.cdi.AuthenticationEvent;
import be.fedict.eid.applet.service.cdi.BeIDContext;
import be.fedict.eid.applet.service.cdi.IdentificationEvent;
import be.fedict.eid.applet.service.cdi.IdentityEvent;
import be.fedict.eid.applet.service.cdi.StartEvent;
import be.fedict.eid.applet.service.cdi.StartEvent.AuthenticationRequest;
import be.fedict.eid.applet.service.cdi.StartEvent.IdentificationRequest;

@Named("cdiTest")
@SessionScoped
public class Controller implements Serializable {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(Controller.class);

	public static enum Operation {
		IDENTIFICATION, AUTHENTICATION, SIGNING
	}

	private Operation operation;

	private Identity identity;

	private String userIdentifier;

	private Address address;

	private boolean includeIdentity;

	private boolean includeAddress;

	private boolean includePhoto;

	public void setOperation(Operation operation) {
		this.operation = operation;
	}

	public Operation getOperation() {
		return this.operation;
	}

	public Operation[] getOperations() {
		return Operation.values();
	}

	public Identity getIdentity() {
		return this.identity;
	}

	public String getUserIdentifier() {
		return this.userIdentifier;
	}

	public Address getAddress() {
		return this.address;
	}

	public boolean isIncludeIdentity() {
		return this.includeIdentity;
	}

	public void setIncludeIdentity(boolean includeIdentity) {
		this.includeIdentity = includeIdentity;
	}

	public boolean isIncludeAddress() {
		return this.includeAddress;
	}

	public void setIncludeAddress(boolean includeAddress) {
		this.includeAddress = includeAddress;
	}

	public boolean isIncludePhoto() {
		return this.includePhoto;
	}

	public void setIncludePhoto(boolean includePhoto) {
		this.includePhoto = includePhoto;
	}

	public void reset() {
		this.identity = null;
		this.address = null;
		this.userIdentifier = null;
	}

	public void perform() throws IOException {
		FacesContext facesContext = FacesContext.getCurrentInstance();
		ExternalContext externalContext = facesContext.getExternalContext();
		externalContext.redirect(externalContext.getRequestContextPath()
				+ "/cdi.html");
	}

	public void handleStart(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) StartEvent startEvent) {
		LOG.debug("start event");
		switch (this.operation) {
		case IDENTIFICATION: {
			IdentificationRequest identificationRequest = startEvent
					.performIdentification();
			if (this.includeAddress) {
				identificationRequest.includeAddress();
			}
			if (this.includePhoto) {
				identificationRequest.includePhoto();
			}
			break;
		}
		case AUTHENTICATION: {
			AuthenticationRequest authenticationRequest = startEvent
					.performAuthentication();
			if (this.includeIdentity) {
				authenticationRequest.includeIdentity();
			}
			if (this.includeAddress) {
				authenticationRequest.includeAddress();
			}
			if (this.includePhoto) {
				authenticationRequest.includePhoto();
			}
			break;
		}
		default:
			throw new IllegalStateException("unsupported operation: "
					+ this.operation);
		}
	}

	public void handleReset(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) StartEvent startEvent) {
		reset();
	}

	public void handleIdentification(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) IdentificationEvent identificationEvent) {
		identificationEvent.valid();
	}

	public void handleIdentity(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) IdentityEvent identityEvent) {
		LOG.debug("handle identity");
		LOG.debug("hello: " + identityEvent.getIdentity().getFirstName());
		this.identity = identityEvent.getIdentity();
		this.address = identityEvent.getAddress();
	}

	public void handleAuthCertValidation(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) AuthenticationEvent authenticationEvent) {
		authenticationEvent.valid();
	}

	public void handleAuthenticatedUser(
			@Observes @BeIDContext(IdentifyCDIServlet.CONTEXT) AuthenticatedEvent authenticatedEvent) {
		this.userIdentifier = authenticatedEvent.getUserIdentifier();
	}
}
