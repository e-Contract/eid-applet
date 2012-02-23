/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class RSATest {

	private static final Log LOG = LogFactory.getLog(RSATest.class);

	@BeforeClass
	public static void setUpClass() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testListSecurityProviders() throws Exception {
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			LOG.debug("provider name: " + provider.getName());
			LOG.debug("provider info: " + provider.getInfo());
			Set<Service> services = provider.getServices();
			for (Service service : services) {
				LOG.debug("\tservice type: " + service.getType());
				LOG.debug("\tservice algo: " + service.getAlgorithm());
			}
		}
	}

	@Test
	public void testPSS() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");

		byte[] data = "hello world".getBytes();

		signature.initSign(privateKey);
		signature.update(data);
		byte[] signatureValue = signature.sign();

		LOG.debug("signature size: " + signatureValue.length);

		LOG.debug("signature value: "
				+ new String(Hex.encodeHex(signatureValue)));

		signature.initVerify(publicKey);
		signature.update(data);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);

		signature.initSign(privateKey);
		signature.update(data);
		byte[] signatureValue2 = signature.sign();

		LOG.debug("signature size: " + signatureValue2.length);

		LOG.debug("signature value: "
				+ new String(Hex.encodeHex(signatureValue2)));

		assertFalse(Arrays.equals(signatureValue, signatureValue2));
	}
}
