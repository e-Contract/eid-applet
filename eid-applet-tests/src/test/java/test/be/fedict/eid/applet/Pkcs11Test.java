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

package test.be.fedict.eid.applet;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.awt.Component;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Status;
import be.fedict.eid.applet.View;
import be.fedict.eid.applet.sc.PcscEid;
import be.fedict.eid.applet.sc.PcscEidSpi;
import be.fedict.eid.applet.sc.Pkcs11Eid;

public class Pkcs11Test {

	private static final Log LOG = LogFactory.getLog(Pkcs11Test.class);

	private Messages messages;

	@Before
	public void setUp() {
		this.messages = new Messages(Locale.getDefault());
	}

	public static class TestView implements View {

		@Override
		public void addDetailMessage(String detailMessage) {
			LOG.debug("detail: " + detailMessage);
		}

		@Override
		public Component getParentComponent() {
			return null;
		}

		@Override
		public boolean privacyQuestion(boolean includeAddress,
				boolean includePhoto) {
			return false;
		}

		@Override
		public void setStatusMessage(Status status, String statusMessage) {
			LOG.debug("status: [" + status + "]: " + statusMessage);
		}

		@Override
		public void progressIndication(int max, int current) {
		}
	}

	@Test
	public void testAuthnSignature() throws Exception {
		Pkcs11Eid pkcs11Eid = new Pkcs11Eid(new TestView(), this.messages);
		if (false == pkcs11Eid.isEidPresent()) {
			LOG.debug("insert eID...");
			pkcs11Eid.waitForEidPresent();
		}

		byte[] challenge = "hello world".getBytes();

		byte[] signatureValue = pkcs11Eid.signAuthn(challenge);
		List<X509Certificate> authnCertChain = pkcs11Eid
				.getAuthnCertificateChain();
		pkcs11Eid.close();

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(authnCertChain.get(0).getPublicKey());
		signature.update(challenge);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);
	}

	@Test
	public void testInsertRemoveCard() throws Exception {
		Pkcs11Eid pkcs11Eid = new Pkcs11Eid(new TestView(), this.messages);
		while (true) {
			if (false == pkcs11Eid.isEidPresent()) {
				LOG.debug("insert eID...");
				pkcs11Eid.waitForEidPresent();
			}
		}
	}

	@Test
	public void testC_GetSlotList() throws Exception {
		Pkcs11Eid pkcs11Eid = new Pkcs11Eid(new TestView(), this.messages);
		pkcs11Eid.isEidPresent();
		PKCS11 pkcs11 = pkcs11Eid.getPkcs11();
		long count = 0;
		while (true) {
			/*
			 * C_GetSlotList(true) throws a CKR_BUFFER_TOO_SMALL exception when
			 * the eID card is inserted/removed very fast. C_GetSlotList(false)
			 * does not have this problem.
			 */
			pkcs11.C_GetSlotList(false);
			LOG.debug("count: " + count++);
		}
	}

	@Test
	public void testAuthnSignatureWithLogoff() throws Exception {
		Pkcs11Eid pkcs11Eid = new Pkcs11Eid(new TestView(), this.messages);
		if (false == pkcs11Eid.isEidPresent()) {
			LOG.debug("insert eID...");
			pkcs11Eid.waitForEidPresent();
		}

		byte[] challenge = "hello world".getBytes();

		byte[] signatureValue = pkcs11Eid.signAuthn(challenge);
		List<X509Certificate> authnCertChain = pkcs11Eid
				.getAuthnCertificateChain();
		String readerName = pkcs11Eid.getSlotDescription();
		LOG.debug("reader name: " + readerName);
		pkcs11Eid.close();

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(authnCertChain.get(0).getPublicKey());
		signature.update(challenge);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);

		PcscEidSpi pcscEid = new PcscEid(new TestView(), this.messages);
		pcscEid.logoff(readerName);
	}

	@Test
	public void sign() throws Exception {
		sign("SHA1", "SHA1withRSA");
	}

	@Test
	public void signSha256() throws Exception {
		sign("SHA-256", "SHA256withRSA");
	}

	@Test
	public void signSha384() throws Exception {
		sign("SHA-384", "SHA384withRSA");
	}

	@Test
	public void signSha512() throws Exception {
		sign("SHA-512", "SHA512withRSA");
	}

	private void sign(String digestAlgo, String signAlgo) throws IOException,
			PKCS11Exception, InterruptedException, NoSuchFieldException,
			IllegalAccessException, InvocationTargetException,
			NoSuchMethodException, NoSuchAlgorithmException, Exception,
			InvalidKeyException, SignatureException {
		Pkcs11Eid pkcs11Eid = new Pkcs11Eid(new TestView(), this.messages);
		if (false == pkcs11Eid.isEidPresent()) {
			LOG.debug("insert eID...");
			pkcs11Eid.waitForEidPresent();
		}

		byte[] message = "hello world".getBytes();

		MessageDigest digest = MessageDigest.getInstance(digestAlgo);
		digest.update(message);
		byte[] digestValue = digest.digest();

		byte[] signatureValue = pkcs11Eid.sign(digestValue, digestAlgo);

		List<X509Certificate> certChain = pkcs11Eid.getSignCertificateChain();

		pkcs11Eid.close();

		Signature signature = Signature.getInstance(signAlgo);
		signature.initVerify(certChain.get(0).getPublicKey());
		signature.update(message);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);
	}

	@Test
	public void signatureVerificationViaDigestValue() throws Exception {
		KeyPair keyPair = generateKeyPair();
		LOG.debug("public RSA key size: "
				+ keyPair.getPublic().getEncoded().length);
		byte[] message = "hello world".getBytes();

		// create signature
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(message);
		byte[] signatureValue = signature.sign();

		// verify signature via original message
		signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(keyPair.getPublic());
		signature.update(message);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);
		LOG.debug("signature value size: " + signatureValue.length);

		// verify signature via digested message
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
		byte[] expectedDigest = messageDigest.digest(message);
		LOG.debug("digest size: " + expectedDigest.length);

		Cipher cipher = Cipher.getInstance("RSA");
		// Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		// KeyPair keyPair2 = generateKeyPair();
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
		byte[] signatureDigest = cipher.doFinal(signatureValue);
		LOG.debug("expected digest length: " + signatureDigest.length);

		ASN1InputStream aIn = new ASN1InputStream(signatureDigest);
		DigestInfo signatureDigestInfo = new DigestInfo((ASN1Sequence) aIn
				.readObject());

		Assert.assertArrayEquals(signatureDigestInfo.getDigest(),
				expectedDigest);
	}

	@Test
	public void testReaderList() throws Exception {
		Pkcs11Eid pkcs11Eid = new Pkcs11Eid(new TestView(), this.messages);
		List<String> readerList = pkcs11Eid.getReaderList();
		assertNotNull(readerList);
		LOG.debug("reader list: " + readerList);
	}

	private KeyPair generateKeyPair(int size) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator;
		keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(size,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private KeyPair generateKeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		KeyPair keyPair = generateKeyPair(1024);
		return keyPair;
	}
}
