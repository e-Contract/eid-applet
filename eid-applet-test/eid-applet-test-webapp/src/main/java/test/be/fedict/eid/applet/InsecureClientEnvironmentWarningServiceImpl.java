/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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

import java.util.List;

import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.spi.InsecureClientEnvironmentException;
import be.fedict.eid.applet.service.spi.SecureClientEnvironmentService;

public class InsecureClientEnvironmentWarningServiceImpl implements
		SecureClientEnvironmentService {

	private static final Log LOG = LogFactory
			.getLog(InsecureClientEnvironmentWarningServiceImpl.class);

	public void checkSecureClientEnvironment(String javaVersion,
			String javaVendor, String osName, String osArch, String osVersion,
			String userAgent, String navigatorAppName,
			String navigatorAppVersion, String navigatorUserAgent,
			String remoteAddress, Integer sslKeySize, String sslCipherSuite,
			List<String> readerList) throws InsecureClientEnvironmentException {
		LOG.debug("insecure warning");

		LOG.debug("java version: " + javaVersion);
		LOG.debug("java vendor: " + javaVendor);
		LOG.debug("OS name: " + osName);
		LOG.debug("OS arch: " + osArch);
		LOG.debug("OS version: " + osVersion);
		LOG.debug("user agent: " + userAgent);
		LOG.debug("navigator app name: " + navigatorAppName);
		LOG.debug("navigator app version: " + navigatorAppVersion);
		LOG.debug("navigator user agent: " + navigatorUserAgent);
		LOG.debug("remote address: " + remoteAddress);
		LOG.debug("ssl key size: " + sslKeySize);
		LOG.debug("ssl cipher suite: " + sslCipherSuite);
		LOG.debug("readers: " + readerList);

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		httpSession.setAttribute("ClientJavaVersion", javaVersion);
		httpSession.setAttribute("ClientJavaVendor", javaVendor);
		httpSession.setAttribute("ClientOSName", osName);
		httpSession.setAttribute("ClientOSArch", osArch);
		httpSession.setAttribute("ClientOSVersion", osVersion);
		httpSession.setAttribute("ClientReaders", readerList.toString());
		httpSession.setAttribute("ClientUserAgent", userAgent);
		httpSession.setAttribute("ClientSslCipherSuite", sslCipherSuite);
		httpSession.setAttribute("ClientRemoteAddress", remoteAddress);
		httpSession.setAttribute("ClientSslKeySize", sslKeySize);
		httpSession
				.setAttribute("ClientNavigatorUserAgent", navigatorUserAgent);
		httpSession.setAttribute("ClientNavigatorAppName", navigatorAppName);
		httpSession.setAttribute("ClientNavigatorAppVersion",
				navigatorAppVersion);

		throw new InsecureClientEnvironmentException(true);
	}
}
