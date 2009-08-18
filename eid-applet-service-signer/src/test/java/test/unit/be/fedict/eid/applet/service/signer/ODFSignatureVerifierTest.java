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

package test.unit.be.fedict.eid.applet.service.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.service.signer.ODFSignatureVerifier;

/**
 * Unit tests for ODF signature verifier.
 * 
 * @author fcorneli
 * 
 */
public class ODFSignatureVerifierTest {

	private static final Log LOG = LogFactory
			.getLog(ODFSignatureVerifierTest.class);

	@Test
	public void testODFWithoutSignature() throws Exception {
		// setup
		URL odfUrl = ODFSignatureVerifierTest.class
				.getResource("/hello-world.odt");

		// operate
		boolean result = ODFSignatureVerifier.hasOdfSignature(odfUrl);

		// verify
		assertFalse(result);
	}

	@Test
	public void testODFSignature() throws Exception {
		// setup
		URL odfUrl = ODFSignatureVerifierTest.class
				.getResource("/hello-world-signed.odt");
		assertNotNull(odfUrl);

		// operate
		boolean result = ODFSignatureVerifier.hasOdfSignature(odfUrl);

		// verify
		assertTrue(result);
	}

	@Test
	public void testODFCoSignature() throws Exception {
		// setup
		URL odfUrl = ODFSignatureVerifierTest.class
				.getResource("/hello-world-signed-twice.odt");
		assertNotNull(odfUrl);

		// operate
		boolean result = ODFSignatureVerifier.hasOdfSignature(odfUrl);

		// verify
		assertTrue(result);
	}

	@Test
	public void testGetSignersEmptyList() throws Exception {
		// setup
		URL odfUrl = ODFSignatureVerifierTest.class
				.getResource("/hello-world.odt");
		assertNotNull(odfUrl);

		// operate
		List<X509Certificate> result = ODFSignatureVerifier.getSigners(odfUrl);

		// verify
		assertNotNull(result);
		assertTrue(result.isEmpty());
	}

	@Test
	public void testGetSigners() throws Exception {
		// setup
		URL odfUrl = ODFSignatureVerifierTest.class
				.getResource("/hello-world-signed.odt");
		assertNotNull(odfUrl);

		// operate
		List<X509Certificate> result = ODFSignatureVerifier.getSigners(odfUrl);

		// verify
		assertNotNull(result);
		assertEquals(1, result.size());
		X509Certificate signer = result.get(0);
		LOG.debug("signer: " + signer.getSubjectX500Principal());
	}

	@Test
	public void testGetSigners2() throws Exception {
		// setup
		URL odfUrl = ODFSignatureVerifierTest.class
				.getResource("/hello-world-signed-twice.odt");
		assertNotNull(odfUrl);

		// operate
		List<X509Certificate> result = ODFSignatureVerifier.getSigners(odfUrl);

		// verify
		assertNotNull(result);
		assertEquals(2, result.size());
		for (X509Certificate signer : result) {
			LOG.debug("signer: " + signer.getSubjectX500Principal());
		}
	}
}
