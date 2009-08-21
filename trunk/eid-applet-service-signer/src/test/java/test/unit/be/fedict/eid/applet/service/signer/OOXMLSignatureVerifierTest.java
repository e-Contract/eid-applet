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

package test.unit.be.fedict.eid.applet.service.signer;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.URL;

import org.junit.Test;

import be.fedict.eid.applet.service.signer.ooxml.OOXMLSignatureVerifier;

public class OOXMLSignatureVerifierTest {

	@Test
	public void testIsOOXMLDocument() throws Exception {
		// setup
		URL url = OOXMLSignatureVerifierTest.class
				.getResource("/hello-world-unsigned.docx");

		// operate
		boolean result = OOXMLSignatureVerifier.isOOXML(url);

		// verify
		assertTrue(result);
	}

	@Test
	public void testODFIsNotOOXML() throws Exception {
		// setup
		URL url = OOXMLSignatureVerifierTest.class
				.getResource("/hello-world.odt");

		// operate
		boolean result = OOXMLSignatureVerifier.isOOXML(url);

		// verify
		assertFalse(result);
	}
}
