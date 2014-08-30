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

import java.awt.Desktop;
import java.net.URI;
import java.net.URLEncoder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

public class DesktopTest {

	private static final Log LOG = LogFactory.getLog(DesktopTest.class);

	@Test
	public void mailto() throws Exception {
		Desktop desktop = Desktop.getDesktop();
		URI mailUri = new URI("mailto:frank.cornelis@fedict.be?subject="
				+ URLEncoder.encode("Hello World", "UTF-8").replaceAll("\\+",
						"%20")
				+ "&cc="
				+ URLEncoder.encode("frank.cornelis@fedict.be", "UTF-8")
				+ "&body="
				+ URLEncoder.encode("test body message", "UTF-8").replaceAll(
						"\\+", "%20"));
		LOG.debug("mail uri: " + mailUri);
		desktop.mail(mailUri);
	}
}
