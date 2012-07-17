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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Set;

import javax.crypto.Cipher;

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
	public void testManualEncryption() throws Exception {
		while (true) {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
					"RSA", BouncyCastleProvider.PROVIDER_NAME);
			SecureRandom random = new SecureRandom();
			int keySize = 128;
			keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize,
					RSAKeyGenParameterSpec.F0), random);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
			LOG.debug("private key modulus: " + rsaPrivateKey.getModulus());
			RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
			LOG.debug("public key modulus: " + rsaPublicKey.getModulus());
			LOG.debug("public key exponent: "
					+ rsaPublicKey.getPublicExponent());
			LOG.debug("modulus size: "
					+ rsaPublicKey.getModulus().toByteArray().length);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);

			int dataSize = keySize / 8 - 11;
			byte[] data1 = new byte[dataSize];
			for (int i = 0; i < data1.length; i++) {
				data1[i] = 0x00;
			}
			byte[] data2 = new byte[dataSize];
			for (int i = 0; i < data2.length; i++) {
				data2[i] = 0x00;
			}
			data2[data2.length - 1] = 0x07;

			byte[] signatureValue1 = cipher.doFinal(data1);

			LOG.debug("signature size: " + signatureValue1.length);

			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] signatureValue2 = cipher.doFinal(data2);

			BigInteger sigBigInt1 = new BigInteger(signatureValue1);
			BigInteger sigBigInt2 = new BigInteger(signatureValue2);
			BigInteger msgBigInt1 = sigBigInt1
					.modPow(rsaPublicKey.getPublicExponent(),
							rsaPublicKey.getModulus());
			BigInteger msgBigInt2 = sigBigInt2
					.modPow(rsaPublicKey.getPublicExponent(),
							rsaPublicKey.getModulus());
			LOG.debug("msg big int: " + msgBigInt1);
			byte[] msgBytes1 = msgBigInt1.toByteArray();
			LOG.debug("original message size: " + msgBytes1.length);
			LOG.debug("original message1: "
					+ new String(Hex.encodeHex(msgBytes1)));
			LOG.debug("original message2: "
					+ new String(Hex.encodeHex(msgBigInt2.toByteArray())));

			LOG.debug("msg1 prime: " + msgBigInt1.isProbablePrime(100));
			LOG.debug("msg2 prime: " + msgBigInt2.isProbablePrime(100));

			// BigInteger.pow offers a very naive implementation
			LOG.debug("calculating s1^e...");
			BigInteger s1_e = sigBigInt1.pow(rsaPublicKey.getPublicExponent()
					.intValue());
			LOG.debug("s1^e: " + s1_e);
			LOG.debug("calculating s2^e...");
			BigInteger s2_e = sigBigInt2.pow(rsaPublicKey.getPublicExponent()
					.intValue());
			LOG.debug("s2^e: " + s2_e);

			LOG.debug("calculating GCD...");
			LOG.debug("msg1: " + msgBigInt1);
			LOG.debug("msg2: " + msgBigInt2);
			BigInteger a = s1_e.subtract(msgBigInt1);
			BigInteger b = s2_e.subtract(msgBigInt2);
			LOG.debug("a: " + a);
			LOG.debug("b: " + b);
			BigInteger candidateModulus = a.gcd(b);
			LOG.debug("candidate modulus: " + candidateModulus);
			LOG.debug("candidate modulus size: "
					+ candidateModulus.toByteArray().length);
			BigInteger s_e = s1_e.multiply(s2_e);
			BigInteger m = msgBigInt1.multiply(msgBigInt2);
			while (false == rsaPublicKey.getModulus().equals(candidateModulus)) {
				LOG.error("incorrect candidate modulus");
				LOG.debug("modulus | candidate modulus: "
						+ candidateModulus.remainder(rsaPublicKey.getModulus())
								.equals(BigInteger.ZERO));
				s_e = s_e.multiply(s1_e);
				m = m.multiply(msgBigInt1);
				BigInteger n1 = s_e.subtract(m).gcd(a);
				BigInteger n2 = s_e.subtract(m).gcd(b);
				candidateModulus = n1.gcd(n2);
				// try / 2
				LOG.debug("new modulus:       " + n1);
				LOG.debug("new modulus:       " + n2);
				LOG.debug("candidate modulus: " + candidateModulus);
				LOG.debug("actual mod:        " + rsaPublicKey.getModulus());
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

		MessageDigest messageDigest = MessageDigest
				.getInstance("SHA-256", "BC");
		byte[] digest = messageDigest.digest(data);

		signature = Signature.getInstance("RAWRSASSA-PSS", "BC");
		signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
				new MGF1ParameterSpec("SHA-256"), 32, 1));
		signature.initVerify(publicKey);
		signature.update(digest);
		result = signature.verify(signatureValue);
		assertTrue(result);
	}
}
