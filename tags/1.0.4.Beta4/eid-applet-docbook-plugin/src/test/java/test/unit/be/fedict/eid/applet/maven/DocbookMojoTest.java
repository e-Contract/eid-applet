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

package test.unit.be.fedict.eid.applet.maven;

import java.io.File;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.maven.DocbookMojo;

public class DocbookMojoTest {

	private static final Log LOG = LogFactory.getLog(DocbookMojoTest.class);

	@Test
	public void testCreateGraph() throws Exception {
		File tmpFile = File.createTempFile("graph-", ".png");

		DocbookMojo.generateGraph(tmpFile);

		LOG.debug("graph file: " + tmpFile.getAbsolutePath());
	}
}
