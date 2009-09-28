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

package be.fedict.eid.applet.service.spi;

import java.util.List;

/**
 * Interface for security environment service components. Can be used by the eID
 * Applet Service to check the client environment security requirements.
 * 
 * @author Frank Cornelis
 * 
 */
public interface SecureClientEnvironmentService {

	/**
	 * Checks whether the client environment is secure enough for this web
	 * application.
	 * 
	 * @param javaVersion
	 *            the version of the Java JRE on the client machine.
	 * @param javaVendor
	 *            the vendor of the Java JRE on the client machine.
	 * @param osName
	 *            the name of the operating system on the client machine.
	 * @param osArch
	 *            the architecture of the client machine.
	 * @param osVersion
	 *            the operating system version of the client machine.
	 * @param userAgent
	 *            the user agent, i.e. browser, used on the client machine.
	 * @param navigatorAppName
	 *            the optional navigator application name (browser)
	 * @param navigatorAppVersion
	 *            the optional navigator application version (browser version)
	 * @param navigatorUserAgent
	 *            the optional optional navigator user agent name.
	 * @param remoteAddress
	 *            the address of the client machine.
	 * @param sslKeySize
	 *            the optional key size of the SSL session used between server
	 *            and client. Can be <code>null</code> in case the SSL is
	 *            terminated early.
	 * @param sslCipherSuite
	 *            the optional cipher suite of the SSL session used between
	 *            server and client. Can be <code>null</code> in case the SSL is
	 *            terminated early.
	 * @param readerList
	 *            the list of smart card readers present on the client machine.
	 * @throws InsecureClientEnvironmentException
	 *             if the client env is found not to be secure enough.
	 */
	void checkSecureClientEnvironment(String javaVersion, String javaVendor,
			String osName, String osArch, String osVersion, String userAgent,
			String navigatorAppName, String navigatorAppVersion,
			String navigatorUserAgent, String remoteAddress,
			Integer sslKeySize, String sslCipherSuite, List<String> readerList)
			throws InsecureClientEnvironmentException;
}
