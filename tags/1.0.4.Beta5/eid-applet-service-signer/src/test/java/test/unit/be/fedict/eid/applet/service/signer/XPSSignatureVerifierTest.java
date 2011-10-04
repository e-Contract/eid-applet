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

package test.unit.be.fedict.eid.applet.service.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.eid.applet.service.signer.ooxml.OOXMLProvider;
import be.fedict.eid.applet.service.signer.xps.XPSSignatureVerifier;

public class XPSSignatureVerifierTest {

	private static final Log LOG = LogFactory
			.getLog(XPSSignatureVerifierTest.class);

	@BeforeClass
	public static void setUp() {
		OOXMLProvider.install();
	}

	@Test
	public void testUnsignedXPS() throws Exception {
		URL documentUrl = XPSSignatureVerifierTest.class
				.getResource("/hello-world.xps");
		assertNotNull(documentUrl);

		// operate
		XPSSignatureVerifier verifier = new XPSSignatureVerifier();
		List<X509Certificate> result = verifier.getSigners(documentUrl);

		// verify
		assertNotNull(result);
		assertTrue(result.isEmpty());
	}

	@Test
	public void testSignedXPS() throws Exception {
		URL documentUrl = XPSSignatureVerifierTest.class
				.getResource("/hello-world-signed.xps");
		assertNotNull(documentUrl);

		// operate
		XPSSignatureVerifier verifier = new XPSSignatureVerifier();
		List<X509Certificate> result = verifier.getSigners(documentUrl);

		// verify
		assertNotNull(result);
		assertEquals(1, result.size());
		X509Certificate signer = result.get(0);
		LOG.debug("signer: " + signer.getSubjectX500Principal());
		assertTrue(signer.getSubjectX500Principal().toString()
				.contains("Frank Cornelis (Signature"));
	}
}
