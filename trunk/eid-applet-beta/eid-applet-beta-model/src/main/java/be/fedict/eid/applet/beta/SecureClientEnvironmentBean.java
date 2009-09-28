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

package be.fedict.eid.applet.beta;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.InsecureClientEnvironmentException;
import be.fedict.eid.applet.service.spi.SecureClientEnvironmentService;

@Stateless
@Local(SecureClientEnvironmentService.class)
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/SecureClientEnvironmentBean")
public class SecureClientEnvironmentBean implements
		SecureClientEnvironmentService {

	private static final Log LOG = LogFactory
			.getLog(SecureClientEnvironmentBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	@EJB
	private SessionContextManager sessionContextManager;

	public void checkSecureClientEnvironment(String javaVersion,
			String javaVendor, String osName, String osArch, String osVersion,
			String userAgent, String navigatorAppName,
			String navigatorAppVersion, String navigatorUserAgent,
			String remoteAddress, Integer sslKeySize, String sslCipherSuite,
			List<String> readerList) throws InsecureClientEnvironmentException {
		String clientEnviromentResult = "java version: " + javaVersion + "\n"
				+ "java vendor: " + javaVendor + "\n" + "OS name: " + osName
				+ "\n" + "OS arch: " + osArch + "\n" + "OS version: "
				+ osVersion + "\n" + "user agent: " + userAgent + "\n"
				+ "navigator app name: " + navigatorAppName + "\n"
				+ "navigator app version: " + navigatorAppVersion + "\n"
				+ "navigator user agent: " + navigatorUserAgent + "\n"
				+ "remote address: " + remoteAddress + "\n" + "ssl key size: "
				+ sslKeySize + "\n" + "ssl cipher suite: " + sslCipherSuite
				+ "\n" + "readers: " + readerList;
		LOG.debug(clientEnviromentResult);

		SessionContextEntity sessionContext = this.sessionContextManager
				.getSessionContext();
		TestResultEntity testResultEntity = new TestResultEntity(
				"Client Environment", clientEnviromentResult, sessionContext);
		this.entityManager.persist(testResultEntity);

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		httpSession.setAttribute("clientJavaVersion", javaVersion);
		httpSession.setAttribute("clientJavaVendor", javaVendor);
		httpSession.setAttribute("clientOSName", osName);
		httpSession.setAttribute("clientOSArch", osArch);
		httpSession.setAttribute("clientOSVersion", osVersion);
		httpSession.setAttribute("clientReaders", readerList.toString());
		httpSession.setAttribute("clientUserAgent", userAgent);
		httpSession.setAttribute("clientSslCipherSuite", sslCipherSuite);
		httpSession.setAttribute("clientRemoteAddress", remoteAddress);
		httpSession.setAttribute("clientSslKeySize", sslKeySize);
		httpSession
				.setAttribute("clientNavigatorUserAgent", navigatorUserAgent);
		httpSession.setAttribute("clientNavigatorAppName", navigatorAppName);
		httpSession.setAttribute("clientNavigatorAppVersion",
				navigatorAppVersion);
	}
}
