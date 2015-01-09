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

import java.io.IOException;
import java.io.Serializable;

import javax.enterprise.context.SessionScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Named;

import be.fedict.eid.applet.service.Identity;

@Named("cdiTest")
@SessionScoped
public class Controller implements Serializable {

	private static final long serialVersionUID = 1L;

	public static enum Operation {
		IDENTIFICATION, AUTHENTICATION, SIGNING
	}

	private Operation operation;

	private Identity identity;

	private String userIdentifier;

	public void setOperation(Operation operation) {
		this.operation = operation;
	}

	public Operation getOperation() {
		return this.operation;
	}

	public Operation[] getOperations() {
		return Operation.values();
	}

	public void setIdentity(Identity identity) {
		this.identity = identity;
	}

	public Identity getIdentity() {
		return this.identity;
	}

	public void setUserIdentifier(String userIdentifier) {
		this.userIdentifier = userIdentifier;
	}

	public String getUserIdentifier() {
		return this.userIdentifier;
	}

	public void reset() {
		this.identity = null;
		this.userIdentifier = null;
	}

	public void back() throws IOException {
		FacesContext facesContext = FacesContext.getCurrentInstance();
		ExternalContext externalContext = facesContext.getExternalContext();
		externalContext.redirect(externalContext.getRequestContextPath()
				+ "/index.html");
	}

	public void perform() throws IOException {
		FacesContext facesContext = FacesContext.getCurrentInstance();
		ExternalContext externalContext = facesContext.getExternalContext();
		externalContext.redirect(externalContext.getRequestContextPath()
				+ "/cdi.html");
	}
}
