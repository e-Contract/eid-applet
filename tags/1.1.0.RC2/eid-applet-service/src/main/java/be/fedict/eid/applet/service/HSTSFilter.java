/*
 * eID Applet Project.
 * Copyright (C) 2012 FedICT.
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

package be.fedict.eid.applet.service;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.impl.ServiceLocator;
import be.fedict.eid.applet.service.spi.StrictTransportSecurityConfig;
import be.fedict.eid.applet.service.spi.TransportService;

/**
 * HTTP Strict-Transport-Security servlet filter.
 * 
 * @author Frank Cornelis
 * 
 */
public class HSTSFilter implements Filter {

	private static final Log LOG = LogFactory.getLog(HSTSFilter.class);

	public static final String TRANSPORT_SERVICE_INIT_PARAM = "TransportService";

	private ServiceLocator<TransportService> transportServiceLocator;

	public void destroy() {
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		TransportService transportService = this.transportServiceLocator
				.locateService();
		if (null == transportService) {
			chain.doFilter(request, response);
			return;
		}
		StrictTransportSecurityConfig hstsConfig = transportService
				.getStrictTransportSecurityConfig();
		if (null == hstsConfig) {
			chain.doFilter(request, response);
			return;
		}
		LOG.debug("adding HSTS header");
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;
		String headerValue = "max-age=" + hstsConfig.getMaxAge();
		if (hstsConfig.isIncludeSubdomains()) {
			headerValue += "; includeSubdomains";
		}
		httpServletResponse.addHeader("Strict-Transport-Security", headerValue);
		chain.doFilter(request, response);
	}

	public void init(FilterConfig config) throws ServletException {
		this.transportServiceLocator = new ServiceLocator<TransportService>(
				TRANSPORT_SERVICE_INIT_PARAM, config);
	}
}
