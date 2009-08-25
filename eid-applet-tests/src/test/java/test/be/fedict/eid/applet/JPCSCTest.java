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

package test.be.fedict.eid.applet;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import com.linuxnet.jpcsc.Context;
import com.linuxnet.jpcsc.PCSC;

/**
 * Integration Test for jpcsc library.
 * 
 * <p>
 * Java 6 Smart Card I/O API on Mac OS X is still missing the underlying
 * implementation. So we could use jpcsc on Mac OS X to be able to readout the
 * eID identity and address files.
 * </p>
 * 
 * @author Frank Cornelis
 * 
 */
public class JPCSCTest {

	private static final Log LOG = LogFactory.getLog(JPCSCTest.class);

	@Test
	public void testLoadLibraryFromJar() throws Exception {
		InputStream jpcscLibraryInputStream = JPCSCTest.class
				.getResourceAsStream("/libjpcsc.so");
		assertNotNull(jpcscLibraryInputStream);
		File tmpFile = File.createTempFile("libjpcsc-", ".so");
		FileOutputStream tmpOutputStream = new FileOutputStream(tmpFile);
		IOUtils.copy(jpcscLibraryInputStream, tmpOutputStream);
		Runtime runtime = Runtime.getRuntime();
		runtime.load(tmpFile.getAbsolutePath());
		Context context = new Context();
		context.EstablishContext(PCSC.SCOPE_SYSTEM, null, null);
		String[] readers = context.ListReaders();
		context.ReleaseContext();
		for (String reader : readers) {
			LOG.debug("reader: " + reader);
		}
	}
}
