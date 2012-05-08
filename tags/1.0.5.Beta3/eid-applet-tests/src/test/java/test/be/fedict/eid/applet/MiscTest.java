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

import java.net.InetAddress;
import java.net.URI;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

public class MiscTest {

	private static final Log LOG = LogFactory.getLog(MiscTest.class);

	@Test
	public void hostname() throws Exception {
		InetAddress address = InetAddress.getLocalHost();
		String hostname = address.getHostName();
		LOG.debug("hostname: " + hostname);
	}

	@Test
	public void siteName() throws Exception {
		URI documentBase = new URI(
				"https://dev.eid.belgium.be/eid-applet-beta/identification.seam");
		LOG.debug("document base URI: " + documentBase);
		String host = documentBase.getHost();
		LOG.debug("host: " + host);
	}
}
