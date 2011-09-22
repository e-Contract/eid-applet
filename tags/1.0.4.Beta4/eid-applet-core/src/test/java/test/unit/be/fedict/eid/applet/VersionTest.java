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

package test.unit.be.fedict.eid.applet;

import static org.junit.Assert.assertNotNull;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.Version;

public class VersionTest {

	private static final Log LOG = LogFactory.getLog(VersionTest.class);

	@Test
	public void testVersion() throws Exception {
		Version version = new Version();
		String applicationVersion = version.getVersion();
		LOG.debug("application version: " + applicationVersion);
		assertNotNull(applicationVersion);
	}
}
