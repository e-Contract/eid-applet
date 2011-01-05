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

package be.fedict.eid.applet.beta.webapp;

import java.io.IOException;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.seam.security.Credentials;
import org.jboss.security.auth.callback.UsernamePasswordHandler;

/**
 * A JAAS login servlet filter using the JBoss Seam credentials.
 * 
 * @author Frank Cornelis
 * 
 */
public class JAASLoginFilter implements Filter {

	private static final Log LOG = LogFactory.getLog(JAASLoginFilter.class);

	public void init(FilterConfig config) throws ServletException {
		LOG.debug("init");
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		LOG.debug("doFilter");
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpSession httpSession = httpRequest.getSession();
		Credentials credentials = (Credentials) httpSession
				.getAttribute("org.jboss.seam.security.credentials");
		LoginContext loginContext = null;
		String username = credentials.getUsername();
		if (null != username) {
			CallbackHandler callbackHandler = new UsernamePasswordHandler(
					username, username);
			try {
				loginContext = new LoginContext("client-login", callbackHandler);
				loginContext.login();
			} catch (LoginException e) {
				throw new ServletException("JAAS login error");
			}
		}
		try {
			chain.doFilter(request, response);
		} finally {
			if (null != loginContext) {
				try {
					loginContext.logout();
				} catch (LoginException e) {
					throw new ServletException("JAAS logout error");
				}
			}
		}
	}

	public void destroy() {
		LOG.debug("destroy");
	}
}
