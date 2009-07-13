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

package test.unit.be.fedict.eid.applet.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.junit.Test;

import be.fedict.eid.applet.service.impl.UserIdentifierUtil;

public class UserIdentifierUtilTest {

	private static final Log LOG = LogFactory.getLog(UserIdentifierUtil.class);

	@Test
	public void testUserIdentifier() throws Exception {
		// setup
		KeyPair keyPair = MiscTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		String userId = "1234";
		X509Certificate certificate = MiscTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test, SERIALNUMBER=" + userId, notBefore,
				notAfter, null, keyPair.getPrivate(), true, 0, null, null);

		// operate
		String result = UserIdentifierUtil.getUserId(certificate);

		// verify
		LOG.debug("user identifier: " + result);
		assertEquals(userId, result);
	}

	@Test
	public void testHMacSha1() throws Exception {
		SecretKey macKey = new SecretKeySpec("1234".getBytes(), "HmacSHA1");
		Mac mac = Mac.getInstance(macKey.getAlgorithm());
		mac.init(macKey);

		byte[] data = "hello world".getBytes();

		mac.update(data);
		byte[] resultHMac = mac.doFinal();

		LOG.debug("size result HMAC-SHA1: " + resultHMac.length);
		String resultHex = new String(Hex.encodeHex(resultHMac)).toUpperCase();
		LOG.debug("result HMAC-SHA1 HEX: " + resultHex);
	}

	@Test
	public void testNonHexSecret() throws Exception {
		// setup
		String userId = "1234";
		String orgId = "fedict";
		String appId = "eid-applet-unit-test";
		String secret = "the-secret-secret";

		// operate & verify
		try {
			UserIdentifierUtil.getNonReversibleCitizenIdentifier(userId, orgId,
					appId, secret);
			fail();
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testTooShortSecret() throws Exception {
		// setup
		String userId = "1234";
		String orgId = "fedict";
		String appId = "eid-applet-unit-test";
		String secret = "1234";

		// operate & verify
		try {
			UserIdentifierUtil.getNonReversibleCitizenIdentifier(userId, orgId,
					appId, secret);
			fail();
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testHexadecimalEncoding() throws Exception {
		char[] encodedMessage = Hex
				.encodeHex("hello world. this is a long message.".getBytes());
		LOG.debug("encoded message: " + new String(encodedMessage));
		byte[] result = Hex.decodeHex(encodedMessage);
		LOG.debug("decoded message: " + new String(result));

		Hex
				.decodeHex("123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
						.trim().toCharArray());
	}

	@Test
	public void testNRCID() throws Exception {
		// setup
		String userId1 = "1234";
		String userId2 = "5678";
		String orgId = "fedict";
		String appId = "eid-applet-unit-test";
		String secret = "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0";

		// operate
		String result1 = UserIdentifierUtil.getNonReversibleCitizenIdentifier(
				userId1, orgId, appId, secret);
		String result2 = UserIdentifierUtil.getNonReversibleCitizenIdentifier(
				userId2, orgId, appId, secret);

		// verify
		assertNotNull(result1);
		assertNotNull(result2);
		LOG.debug("NRCID 1: " + result1);
		LOG.debug("NRCID 2: " + result2);
		assertFalse(result1.equals(result2));
		assertFalse(result1.contains(userId1));
		assertFalse(result1.contains(userId1));

		// verify stability
		String result1b = UserIdentifierUtil.getNonReversibleCitizenIdentifier(
				userId1, orgId, appId, secret);
		assertEquals(result1, result1b);

		assertFalse(result1.equals(UserIdentifierUtil
				.getNonReversibleCitizenIdentifier(userId1, orgId, appId,
						secret + "1234")));
		assertFalse(result1.equals(UserIdentifierUtil
				.getNonReversibleCitizenIdentifier(userId1, orgId + "foobar",
						appId, secret)));
		assertFalse(result1.equals(UserIdentifierUtil
				.getNonReversibleCitizenIdentifier(userId1, orgId, appId
						+ "foobar", secret)));
	}
}
