/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

public class MSCAPITest {

	private static final Log LOG = LogFactory.getLog(MSCAPITest.class);

	@Test
	public void testMSCAPI() throws Exception {
		KeyStore keyStore = KeyStore.getInstance("Windows-MY");
		keyStore.load(null, null);
		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			LOG.debug("alias: " + alias);
			X509Certificate certificate = (X509Certificate) keyStore
					.getCertificate(alias);
			LOG.debug("certificate subject: "
					+ certificate.getSubjectX500Principal());
		}
	}
}
