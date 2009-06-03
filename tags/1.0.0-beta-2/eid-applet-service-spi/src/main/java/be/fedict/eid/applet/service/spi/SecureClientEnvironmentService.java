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
 * @author fcorneli
 * 
 */
public interface SecureClientEnvironmentService {

	/**
	 * Checks whether the client environment is secure enough for this web
	 * application.
	 * 
	 * @param javaVersion
	 * @param javaVendor
	 * @param osName
	 * @param osArch
	 * @param osVersion
	 * @param userAgent
	 * @param navigatorAppName
	 *            optional
	 * @param navigatorAppVersion
	 *            optional
	 * @param navigatorUserAgent
	 *            optional
	 * @param remoteAddress
	 * @param sslKeySize
	 * @param sslCipherSuite
	 * @param readerList
	 * @throws InsecureClientEnvironmentException
	 *             if the client env is not secure enough.
	 */
	void checkSecureClientEnvironment(String javaVersion, String javaVendor,
			String osName, String osArch, String osVersion, String userAgent,
			String navigatorAppName, String navigatorAppVersion,
			String navigatorUserAgent, String remoteAddress, int sslKeySize,
			String sslCipherSuite, List<String> readerList)
			throws InsecureClientEnvironmentException;
}
