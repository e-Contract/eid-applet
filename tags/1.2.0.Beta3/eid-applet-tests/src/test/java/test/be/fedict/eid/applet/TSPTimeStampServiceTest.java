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

import static org.junit.Assert.assertNotNull;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import be.fedict.eid.applet.service.signer.facets.RevocationData;
import be.fedict.eid.applet.service.signer.time.TSPTimeStampService;
import be.fedict.eid.applet.service.signer.time.TimeStampServiceValidator;
import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.TrustValidator;

/**
 * Integration test for the TSPTimeStampService class.
 * 
 * @author Frank Cornelis
 * 
 */
public class TSPTimeStampServiceTest {

	private static final String TSP_URL = "http://tsa.belgium.be/connect";

	private static final String PROXY_HOST = "proxy.yourict.net";

	private static final int PROXY_PORT = 8080;

	static {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@Test
	public void testGetTimeStamp() throws Exception {
		// setup
		TimeStampServiceValidator validator = new TimeStampServiceTestValidator(
				PROXY_HOST, PROXY_PORT);
		TSPTimeStampService service = new TSPTimeStampService(TSP_URL,
				validator, null, null);
		service.setProxy(PROXY_HOST, PROXY_PORT);
		service.setDigestAlgo("SHA-1");

		byte[] data = "hello world".getBytes();

		// operate
		byte[] result = service.timeStamp(data, null);

		// verify
		assertNotNull(result);
	}

	@Test
	public void testGetTimeStampVerisign() throws Exception {
		// setup
		TimeStampServiceValidator validator = new TimeStampServiceTestValidator(
				PROXY_HOST, PROXY_PORT);
		// NOK: http://timestamp.verisign.com/scripts/timstamp.dll
		// NOK: http://timestamp.verisign.com/scripts/timestamp.dll
		// OK: http://timestamp.globalsign.com/scripts/timstamp.dll
		// NOK: http://www.trustcenter.de/codesigning/timestamp
		// http://timestamp.comodoca.com/authenticode
		TSPTimeStampService service = new TSPTimeStampService(
				"http://timestamp.comodoca.com/authenticode",
				validator, null, null);
		service.setProxy(PROXY_HOST, PROXY_PORT);
		service.setDigestAlgo("SHA-1");

		byte[] data = "hello world".getBytes();

		// operate
		byte[] result = service.timeStamp(data, null);

		// verify
		assertNotNull(result);
	}

	@Test
	public void testGetTimeStampSHA256() throws Exception {
		// setup
		TimeStampServiceValidator validator = new TimeStampServiceTestValidator(
				PROXY_HOST, PROXY_PORT);
		TSPTimeStampService service = new TSPTimeStampService(TSP_URL,
				validator, null, null);
		service.setProxy(PROXY_HOST, PROXY_PORT);
		service.setDigestAlgo("SHA-256");

		byte[] data = "hello world".getBytes();

		// operate
		byte[] result = service.timeStamp(data, null);

		// verify
		assertNotNull(result);
	}

	@Test
	public void testGetTimeStampSHA384() throws Exception {
		// setup
		TimeStampServiceValidator validator = new TimeStampServiceTestValidator(
				PROXY_HOST, PROXY_PORT);
		TSPTimeStampService service = new TSPTimeStampService(TSP_URL,
				validator, null, null);
		service.setProxy(PROXY_HOST, PROXY_PORT);
		service.setDigestAlgo("SHA-384");

		byte[] data = "hello world".getBytes();

		// operate
		byte[] result = service.timeStamp(data, null);

		// verify
		assertNotNull(result);
	}

	@Test
	public void testGetTimeStampSHA512() throws Exception {
		// setup
		TimeStampServiceValidator validator = new TimeStampServiceTestValidator(
				PROXY_HOST, PROXY_PORT);
		TSPTimeStampService service = new TSPTimeStampService(TSP_URL,
				validator, null, null);
		service.setProxy(PROXY_HOST, PROXY_PORT);
		service.setDigestAlgo("SHA-512");

		byte[] data = "hello world".getBytes();

		// operate
		byte[] result = service.timeStamp(data, null);

		// verify
		assertNotNull(result);
	}

	@Test
	public void testGetTimeStampPolicy() throws Exception {
		// setup
		TimeStampServiceValidator validator = new TimeStampServiceTestValidator(
				PROXY_HOST, PROXY_PORT);
		TSPTimeStampService service = new TSPTimeStampService(TSP_URL,
				validator, "2.16.56.9.3.1", null);
		service.setProxy(PROXY_HOST, PROXY_PORT);
		service.setDigestAlgo("SHA-512");

		byte[] data = "hello world".getBytes();

		// operate
		byte[] result = service.timeStamp(data, null);

		// verify
		assertNotNull(result);
	}

	private static class TimeStampServiceTestValidator implements
			TimeStampServiceValidator {

		private static final Log LOG = LogFactory
				.getLog(TimeStampServiceTestValidator.class);

		private final TrustValidator trustValidator;

		public TimeStampServiceTestValidator(String proxyHost, int proxyPort) {
			NetworkConfig networkConfig;
			if (null != proxyHost) {
				networkConfig = new NetworkConfig(proxyHost, proxyPort);
			} else {
				networkConfig = null;
			}
			this.trustValidator = BelgianTrustValidatorFactory
					.createTSATrustValidator(networkConfig, null);
		}

		@Override
		public void validate(List<X509Certificate> certificateChain,
				RevocationData revocationData) throws Exception {
			for (X509Certificate certificate : certificateChain) {
				LOG.debug("certificate: "
						+ certificate.getSubjectX500Principal());
				LOG.debug("validity: " + certificate.getNotBefore() + " - "
						+ certificate.getNotAfter());
			}
			this.trustValidator.isTrusted(certificateChain);
		}
	}
}
