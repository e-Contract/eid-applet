/*
 * eID Applet Project.
 * Copyright (C) 2011 FedICT.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.sc.PcscEid;

/**
 * Integration tests for the new secure pinpad readers from FedICT.
 * <p/>
 * These readers implement the specifications as described at:
 * http://code.google.com/p/eid-applet/wiki/SmartCardReader
 * 
 * @author Frank Cornelis
 * 
 */
public class SecurePinPadReaderTest {

	private static final Log LOG = LogFactory
			.getLog(SecurePinPadReaderTest.class);

	private Messages messages;

	private PcscEid pcscEid;

	/**
	 * To aid the acceptance of the secure smart card reader we use specific QA
	 * annotations to mark integration tests.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	@Documented
	public @interface QualityAssurance {
		Firmware firmware();

		boolean approved();
	}

	/**
	 * Enumeration of the different versions of firmware.
	 */
	public enum Firmware {
		/**
		 * First test sample provided at 18/08/2011.
		 */
		V006Z,
		/**
		 * Second test sample provided at 13/10/2011.
		 */
		V010Z,
		/**
		 * Fourth test sample provided at 14/02/2012.
		 */
		V012Z,
		/**
		 * Not applicable.
		 */
		NA
	}

	@Before
	public void beforeTest() throws Exception {
		this.messages = new Messages(new Locale("nl"));
		this.pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == this.pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			this.pcscEid.waitForEidPresent();
		}
	}

	@After
	public void afterTest() throws Exception {
		this.pcscEid.close();
	}

	/**
	 * Creates a regular SHA1 signature using the non-repudiation key.
	 * <p/>
	 * Remark: right now you have to wait until the digest value has been
	 * scrolled completely before being able to continue.
	 * <p/>
	 * Remark: The smart card reader does not honor the wLangId of the CCID pin
	 * verification data structure yet. V010Z still does not honor the wLangId
	 * <p/>
	 * V010Z: the reader first displays "Sign Hash?", then it requests the
	 * "Authentication PIN?" and then it asks to "Sign Hash?" again. This is due
	 * to the way the eID Applet code has been constructed.
	 * <p/>
	 * V012Z still does not honor the wLangId.
	 * 
	 * 
	 * @throws Exception
	 */
	@Test
	@QualityAssurance(firmware = Firmware.V012Z, approved = false)
	public void testRegularDigestValueWithNonRepudiation() throws Exception {
		this.pcscEid.sign("hello world".getBytes(), "SHA1");
	}

	/**
	 * Secure PIN Entry Capabilities
	 * <p/>
	 * PC/SC specs Interoperability Specification for ICCs and Personal Computer
	 * Systems Part 10 IFDs with Secure PIN Entry Capabilities allow room for
	 * vendor specific feature tags within the range of 0x80 – 0xFE. So we could
	 * add a feature tag to indicate the specific capabilities of the new smart
	 * card readers. This would allow us to have better user interaction. I.e.
	 * when the smart card readers asks for validation of the digest value, the
	 * software UI could display some info message that you have to check the
	 * reader display to be able to continue.
	 * <p/>
	 * V012Z indicates ffffff80, so 0x80.
	 * 
	 * @see http
	 *      ://www.pcscworkgroup.com/specifications/files/pcsc10_v2.02.08.pdf
	 * @throws Exception
	 */
	@Test
	@QualityAssurance(firmware = Firmware.V012Z, approved = true)
	public void testGetCCIDFeatures() throws Exception {
		int ioctl;
		String osName = System.getProperty("os.name");
		if (osName.startsWith("Windows")) {
			ioctl = (0x31 << 16 | (3400) << 2);
		} else {
			ioctl = 0x42000D48;
		}
		byte[] features = this.pcscEid.getCard().transmitControlCommand(ioctl,
				new byte[0]);
		int idx = 0;
		while (idx < features.length) {
			byte tag = features[idx];
			idx++;
			idx++;
			LOG.debug("CCID feature tag: " + Integer.toHexString(tag));
			idx += 4;
		}
	}

	@Test
	@QualityAssurance(firmware = Firmware.V010Z, approved = true)
	public void testRegularDigestValueWithAuth() throws Exception {
		byte[] signatureValue = this.pcscEid
				.signAuthn("hello world".getBytes());
		LOG.debug("signature value size: " + signatureValue.length);
		assertEquals(128, signatureValue.length);
	}

	@Test
	@QualityAssurance(firmware = Firmware.V012Z, approved = true)
	public void testPlainTextAuthn() throws Exception {
		// operate
		String testMessage = "Test Application @ 14/2/2012 14:48:21";
		byte[] signatureValue = this.pcscEid.sign(testMessage.getBytes(),
				"2.16.56.1.2.1.3.1", (byte) 0x82, false);

		// verify
		List<X509Certificate> authnCertChain = this.pcscEid
				.getAuthnCertificateChain();

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, authnCertChain.get(0));
		byte[] signatureDigestInfoValue = cipher.doFinal(signatureValue);
		ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
		DigestInfo signatureDigestInfo = new DigestInfo(
				(ASN1Sequence) aIn.readObject());
		LOG.debug("result algo Id: "
				+ signatureDigestInfo.getAlgorithmId().getObjectId().getId());
		assertEquals("2.16.56.1.2.1.3.1", signatureDigestInfo.getAlgorithmId()
				.getObjectId().getId());
		assertArrayEquals(testMessage.getBytes(),
				signatureDigestInfo.getDigest());
	}

	/**
	 * Create a plain text authentication signature, directly after creating a
	 * regular SHA1 authentication signature. This is the sequence that will be
	 * implemented in the eID Applet.
	 * <p/>
	 * V006Z: Remark: without the SET APDU the secure smart card reader won't
	 * display the plain text message. Fixed in V010Z.
	 * <p/>
	 * V012Z: language support is still shaky.
	 * 
	 * @throws Exception
	 */
	@Test
	@QualityAssurance(firmware = Firmware.V012Z, approved = false)
	public void testAuthnSignPlainText() throws Exception {
		CardChannel cardChannel = this.pcscEid.getCardChannel();

		List<X509Certificate> authnCertChain = this.pcscEid
				.getAuthnCertificateChain();
		/*
		 * Make sure that the PIN authorization is already OK.
		 */
		this.pcscEid.signAuthn("hello world".getBytes());

		CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
				new byte[] { 0x04, // length of following data
						(byte) 0x80, // algo ref
						0x01, // rsa pkcs#1
						(byte) 0x84, // tag for private key ref
						(byte) 0x82 }); // auth key
		// ResponseAPDU responseApdu = cardChannel.transmit(setApdu);
		// assertEquals(0x9000, responseApdu.getSW());

		String textMessage = "My Testcase";
		AlgorithmIdentifier algoId = new AlgorithmIdentifier(
				"2.16.56.1.2.1.3.1");
		DigestInfo digestInfo = new DigestInfo(algoId, textMessage.getBytes());
		LOG.debug("DigestInfo DER encoded: "
				+ new String(Hex.encodeHex(digestInfo.getDEREncoded())));
		CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
				0x9E, 0x9A, digestInfo.getDEREncoded());

		ResponseAPDU responseApdu2 = cardChannel
				.transmit(computeDigitalSignatureApdu);
		assertEquals(0x9000, responseApdu2.getSW());
		byte[] signatureValue = responseApdu2.getData();
		LOG.debug("signature value size: " + signatureValue.length);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, authnCertChain.get(0));
		byte[] signatureDigestInfoValue = cipher.doFinal(signatureValue);
		ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
		DigestInfo signatureDigestInfo = new DigestInfo(
				(ASN1Sequence) aIn.readObject());
		LOG.debug("result algo Id: "
				+ signatureDigestInfo.getAlgorithmId().getObjectId().getId());
		assertEquals("2.16.56.1.2.1.3.1", signatureDigestInfo.getAlgorithmId()
				.getObjectId().getId());
		assertArrayEquals(textMessage.getBytes(),
				signatureDigestInfo.getDigest());
	}

	/**
	 * Creates a non-repudiation signature with plain text.
	 * <p/>
	 * Remark: "Enter NonRep PIN" should maybe be replaced with
	 * "Enter Sign PIN". Fixed in V010Z.
	 * 
	 * @throws Exception
	 */
	@Test
	@QualityAssurance(firmware = Firmware.V012Z, approved = true)
	public void testNonRepSignPlainText() throws Exception {
		CardChannel cardChannel = this.pcscEid.getCardChannel();

		List<X509Certificate> signCertChain = this.pcscEid
				.getSignCertificateChain();

		CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
				new byte[] { 0x04, // length of following data
						(byte) 0x80, // algo ref
						0x01, // rsa pkcs#1
						(byte) 0x84, // tag for private key ref
						(byte) 0x83 }); // non-rep key
		ResponseAPDU responseApdu = cardChannel.transmit(setApdu);
		assertEquals(0x9000, responseApdu.getSW());

		this.pcscEid.verifyPin();

		String textMessage = "My Testcase";
		AlgorithmIdentifier algoId = new AlgorithmIdentifier(
				"2.16.56.1.2.1.3.1");
		DigestInfo digestInfo = new DigestInfo(algoId, textMessage.getBytes());
		CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
				0x9E, 0x9A, digestInfo.getDEREncoded());

		responseApdu = cardChannel.transmit(computeDigitalSignatureApdu);
		assertEquals(0x9000, responseApdu.getSW());
		byte[] signatureValue = responseApdu.getData();
		LOG.debug("signature value size: " + signatureValue.length);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, signCertChain.get(0));
		byte[] signatureDigestInfoValue = cipher.doFinal(signatureValue);
		ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
		DigestInfo signatureDigestInfo = new DigestInfo(
				(ASN1Sequence) aIn.readObject());
		LOG.debug("result algo Id: "
				+ signatureDigestInfo.getAlgorithmId().getObjectId().getId());
		assertEquals("2.16.56.1.2.1.3.1", signatureDigestInfo.getAlgorithmId()
				.getObjectId().getId());
		assertArrayEquals(textMessage.getBytes(),
				signatureDigestInfo.getDigest());
	}

	@Test
	@QualityAssurance(firmware = Firmware.V012Z, approved = false)
	public void testLargePlainTextMessage() throws Exception {
		CardChannel cardChannel = this.pcscEid.getCardChannel();

		List<X509Certificate> signCertChain = this.pcscEid
				.getSignCertificateChain();

		CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
				new byte[] { 0x04, // length of following data
						(byte) 0x80, // algo ref
						0x01, // rsa pkcs#1
						(byte) 0x84, // tag for private key ref
						(byte) 0x83 }); // non-rep key
		ResponseAPDU responseApdu = cardChannel.transmit(setApdu);
		assertEquals(0x9000, responseApdu.getSW());

		this.pcscEid.verifyPin();

		byte[] data = new byte[115];
		/*
		 * If the length of the plain text message is >= 115, the message is not
		 * visualized by the secure pinpad reader.
		 */
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(data);
		AlgorithmIdentifier algoId = new AlgorithmIdentifier(
				"2.16.56.1.2.1.3.1");
		DigestInfo digestInfo = new DigestInfo(algoId, data);
		CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
				0x9E, 0x9A, digestInfo.getDEREncoded());

		responseApdu = cardChannel.transmit(computeDigitalSignatureApdu);
		assertEquals(0x9000, responseApdu.getSW());
		byte[] signatureValue = responseApdu.getData();
		LOG.debug("signature value size: " + signatureValue.length);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, signCertChain.get(0));
		byte[] signatureDigestInfoValue = cipher.doFinal(signatureValue);
		ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
		DigestInfo signatureDigestInfo = new DigestInfo(
				(ASN1Sequence) aIn.readObject());
		LOG.debug("result algo Id: "
				+ signatureDigestInfo.getAlgorithmId().getObjectId().getId());
		assertEquals("2.16.56.1.2.1.3.1", signatureDigestInfo.getAlgorithmId()
				.getObjectId().getId());
		assertArrayEquals(data, signatureDigestInfo.getDigest());
	}

	/**
	 * When creating a non-repudiation signature using PKCS#1-SHA1 (non-naked)
	 * the digest value should also be confirmed via the secure pinpad reader.
	 * 
	 * @throws Exception
	 */
	@Test
	@QualityAssurance(firmware = Firmware.V012Z, approved = false)
	public void testNonRepSignPKCS1_SHA1() throws Exception {
		CardChannel cardChannel = this.pcscEid.getCardChannel();

		List<X509Certificate> signCertChain = this.pcscEid
				.getSignCertificateChain();

		CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
				new byte[] { 0x04, // length of following data
						(byte) 0x80, // algo ref
						0x02, // RSA PKCS#1 SHA1
						(byte) 0x84, // tag for private key ref
						(byte) 0x83 }); // non-rep key
		ResponseAPDU responseApdu = cardChannel.transmit(setApdu);
		assertEquals(0x9000, responseApdu.getSW());

		this.pcscEid.verifyPin();

		byte[] data = "My Testcase".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] digestValue = messageDigest.digest(data);

		CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
				0x9E, 0x9A, digestValue);

		responseApdu = cardChannel.transmit(computeDigitalSignatureApdu);
		assertEquals(0x9000, responseApdu.getSW());
		byte[] signatureValue = responseApdu.getData();
		LOG.debug("signature value size: " + signatureValue.length);

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(signCertChain.get(0).getPublicKey());
		signature.update(data);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);
	}

	@Test
	@QualityAssurance(firmware = Firmware.NA, approved = true)
	public void testQualityAssurance() throws Exception {
		LOG.debug("Quality Assurance report");
		LOG.debug("Date: " + new Date());
		LOG.debug("Tester: " + System.getProperty("user.name"));
		Method[] methods = SecurePinPadReaderTest.class.getMethods();
		for (Method method : methods) {
			Test testAnnotation = method.getAnnotation(Test.class);
			if (null == testAnnotation) {
				continue;
			}
			QualityAssurance qualityAssuranceAnnotation = method
					.getAnnotation(QualityAssurance.class);
			if (null == qualityAssuranceAnnotation) {
				throw new RuntimeException("missing QualityAssurance status");
			}
			LOG.debug("Test: " + method.getName());
			LOG.debug("\tFirmware version: "
					+ qualityAssuranceAnnotation.firmware());
			LOG.debug("\tApproved: " + qualityAssuranceAnnotation.approved());
		}
	}
}
