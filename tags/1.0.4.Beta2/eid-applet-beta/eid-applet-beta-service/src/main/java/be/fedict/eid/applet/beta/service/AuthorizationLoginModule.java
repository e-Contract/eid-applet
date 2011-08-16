/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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

package be.fedict.eid.applet.beta.service;

import java.security.acl.Group;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * JAAS Login Module for assigning a principal JBoss Roles.
 * 
 * @author Frank Cornelis
 * 
 */
public class AuthorizationLoginModule implements LoginModule {

	private static final Log LOG = LogFactory
			.getLog(AuthorizationLoginModule.class);

	private Subject subject;

	private CallbackHandler callbackHandler;

	private Map<String, ?> sharedState;

	private Map<String, ?> options;

	private NamePrincipal principal;

	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;
	}

	public boolean login() throws LoginException {
		NameCallback nameCallback = new NameCallback("Username");
		Callback[] callbacks = new Callback[] { nameCallback };
		try {
			this.callbackHandler.handle(callbacks);
		} catch (Exception e) {
			throw new LoginException("JAAS callback error: " + e.getMessage());
		}
		String name = nameCallback.getName();
		this.principal = new NamePrincipal(name);
		LOG.debug("login: " + name);
		return true;
	}

	public boolean commit() throws LoginException {
		this.subject.getPrincipals().add(this.principal);
		/*
		 * JBoss Roles
		 */
		Group roleGroup = new SimpleGroup("Roles");
		NamePrincipal adminRole = new NamePrincipal("admin");
		roleGroup.addMember(adminRole);
		this.subject.getPrincipals().add(roleGroup);
		return true;
	}

	public boolean abort() throws LoginException {
		this.principal = null;
		this.subject.getPrincipals().clear();
		return true;
	}

	public boolean logout() throws LoginException {
		this.principal = null;
		this.subject.getPrincipals().clear();
		return true;
	}
}