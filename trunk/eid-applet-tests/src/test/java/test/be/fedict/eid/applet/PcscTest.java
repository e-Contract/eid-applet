/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.imageio.ImageIO;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.View;
import be.fedict.eid.applet.sc.Constants;
import be.fedict.eid.applet.sc.PcscEid;
import be.fedict.eid.applet.sc.Task;
import be.fedict.eid.applet.sc.TaskRunner;
import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.impl.tlv.TlvField;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;
import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.FallbackTrustLinker;
import be.fedict.trust.MemoryCertificateRepository;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.PublicKeyTrustLinker;
import be.fedict.trust.RevocationData;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.crl.CachedCrlRepository;
import be.fedict.trust.crl.CrlTrustLinker;
import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.ocsp.OcspTrustLinker;
import be.fedict.trust.ocsp.OnlineOcspRepository;

/**
 * Integration tests for PC/SC eID component.
 * 
 * @author Frank Cornelis
 * 
 */
public class PcscTest {

	static final Log LOG = LogFactory.getLog(PcscTest.class);

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	private Messages messages;

	@Before
	public void setUp() {
		this.messages = new Messages(Locale.getDefault());
	}

	@Test
	public void pcscAuthnSignature() throws Exception {
		this.messages = new Messages(Locale.GERMAN);
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		// PPDU test
		pcscEid.addPPDUName("digipass 870");

		byte[] challenge = "hello world".getBytes();
		byte[] signatureValue;
		List<X509Certificate> authnCertChain;
		try {
			// pcscEid.logoff();
			// pcscEid.selectBelpicJavaCardApplet();
			signatureValue = pcscEid.signAuthn(challenge);

			long t0 = System.currentTimeMillis();
			pcscEid.signAuthn(challenge);
			long t1 = System.currentTimeMillis();
			LOG.debug("dt: " + (t1 - t0));

			authnCertChain = pcscEid.getAuthnCertificateChain();
			LOG.debug("key size: "
					+ authnCertChain.get(0).getPublicKey().getEncoded().length
					* 8);
			// pcscEid.logoff();
		} finally {
			pcscEid.close();
		}

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(authnCertChain.get(0).getPublicKey());
		signature.update(challenge);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);
		LOG.debug("sha1 hex: "
				+ DigestUtils.shaHex(authnCertChain.get(0).getPublicKey()
						.getEncoded()));
	}

	@Test
	public void pcscMSE_SET() throws Exception {
		this.messages = new Messages(Locale.GERMAN);
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		CardChannel cardChannel = pcscEid.getCardChannel();
		try {
			CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
					new byte[] { 0x04, // length of following data
							(byte) 0x80, // algo ref
							// 0x01, // rsa pkcs#1
							// 0x02, // PKCS1-SHA1
							// 0x04, // PKCS1-MD5
							// 0x08, // PKCS1-SHA256
							// 0x10, // PKCS1-PSS-SHA1
							0x20, // PKCS1-PSS-SHA256
							// (byte) 0xfb, // foobar
							(byte) 0x84, // tag for private key ref
							PcscEid.AUTHN_KEY_ID });
			ResponseAPDU responseAPDU = cardChannel.transmit(setApdu);
			assertEquals(0x9000, responseAPDU.getSW());
		} finally {
			pcscEid.close();
		}
	}

	@Test
	public void createPSSSignature() throws Exception {
		this.messages = new Messages(Locale.GERMAN);
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		CardChannel cardChannel = pcscEid.getCardChannel();

		byte[] message = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] digest = messageDigest.digest(message);

		try {
			CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
					new byte[] { 0x04, // length of following data
							(byte) 0x80, // algo ref
							0x10, // PKCS1-PSS-SHA1
							(byte) 0x84, // tag for private key ref
							PcscEid.AUTHN_KEY_ID });
			ResponseAPDU responseAPDU = cardChannel.transmit(setApdu);
			assertEquals(0x9000, responseAPDU.getSW());

			pcscEid.verifyPin();

			CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00,
					0x2A, 0x9E, 0x9A, digest);
			responseAPDU = cardChannel.transmit(computeDigitalSignatureApdu);
			assertEquals(0x9000, responseAPDU.getSW());

			byte[] signatureValue = responseAPDU.getData();

			LOG.debug("signature value length: " + signatureValue.length);

			List<X509Certificate> authnCertificateChain = pcscEid
					.getAuthnCertificateChain();

			Signature signature = Signature
					.getInstance("SHA1withRSA/PSS", "BC");
			signature.initVerify(authnCertificateChain.get(0).getPublicKey());
			signature.update(message);
			boolean result = signature.verify(signatureValue);
			assertTrue(result);
		} finally {
			pcscEid.close();
		}
	}

	@Test
	public void pcscOTPSpike() throws Exception {
		this.messages = new Messages(Locale.GERMAN);
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		byte[] challenge1 = "123456".getBytes();
		byte[] challenge2 = "654321".getBytes();
		byte[] signatureValue1;
		byte[] signatureValue2;
		List<X509Certificate> authnCertChain;
		try {
			signatureValue1 = pcscEid.signAuthn(challenge1);
			signatureValue2 = pcscEid.signAuthn(challenge2);
			authnCertChain = pcscEid.getAuthnCertificateChain();
		} finally {
			pcscEid.close();
		}

		byte[] sv1 = Arrays.copyOf(signatureValue1, 13);
		byte[] sv2 = Arrays.copyOf(signatureValue2, 13);
		LOG.debug("same encrypted prefix: " + Arrays.equals(sv1, sv2));

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(authnCertChain.get(0).getPublicKey());
		signature.update(challenge1);
		boolean result = signature.verify(signatureValue1);
		assertTrue(result);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, authnCertChain.get(0).getPublicKey());
		byte[] signatureDigestInfoValue = cipher.doFinal(signatureValue1);
		LOG.debug("encrypted signature value: " + signatureValue1.length);
		ASN1InputStream aIn = new ASN1InputStream(signatureDigestInfoValue);
		DigestInfo signatureDigestInfo = new DigestInfo(
				(ASN1Sequence) aIn.readObject());
		LOG.debug("algo OID: "
				+ signatureDigestInfo.getAlgorithmId().getObjectId().getId());
		LOG.debug("digest size: " + signatureDigestInfo.getDigest().length);
		int digestIndex = findSubArray(signatureDigestInfoValue,
				signatureDigestInfo.getDigest());
		assertTrue(-1 != digestIndex);
		LOG.debug("digest index: " + digestIndex);

		// inject the encrypted digest of signature1 into signature2
		// padding will look bad now
		System.arraycopy(signatureValue1, 13, signatureValue2, 13, 20);
		cipher = Cipher.getInstance("RSA/ECB/nopadding");
		cipher.init(Cipher.DECRYPT_MODE, authnCertChain.get(0).getPublicKey());
		signatureValue2 = Arrays.copyOf(signatureValue2, 13 + 20);
		byte[] signatureDigestInfoValue2 = cipher.doFinal(signatureValue2);
		LOG.debug("decrypted structure size: "
				+ signatureDigestInfoValue2.length);
		signatureDigestInfoValue2 = Arrays.copyOf(signatureDigestInfoValue2,
				13 + 20);
		LOG.debug("decrypted structure size (truncated): "
				+ signatureDigestInfoValue2.length);
		ASN1InputStream aIn2 = new ASN1InputStream(signatureDigestInfoValue2);
		DigestInfo signatureDigestInfo2 = new DigestInfo(
				(ASN1Sequence) aIn2.readObject());
		LOG.debug("digest size: " + signatureDigestInfo2.getDigest().length);
		LOG.debug("digest: " + new String(signatureDigestInfo2.getDigest()));
	}

	private int findSubArray(byte[] array, byte[] subarray) {
		LOG.debug("array size: " + array.length);
		LOG.debug("subarray size: " + subarray.length);
		for (int idx = 0; idx < array.length - subarray.length + 1; idx++) {
			byte[] currentSubArray = Arrays.copyOfRange(array, idx, idx
					+ subarray.length);
			LOG.debug("subarray size: " + currentSubArray.length);
			if (Arrays.equals(currentSubArray, subarray)) {
				return idx;
			}
		}
		return -1;
	}

	@Test
	public void pcscAuthnSignatureWithCardRemoval() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		byte[] challenge = "hello world".getBytes();
		try {
			pcscEid.signAuthn(challenge);
			pcscEid.getAuthnCertificateChain();
			LOG.debug("remove card");
			pcscEid.removeCard();
		} finally {
			pcscEid.close();
		}
	}

	@Test
	public void testLocale() throws Exception {
		Locale locale = Locale.GERMAN;
		LOG.debug("locale: " + locale.getLanguage());
	}

	@Test
	public void testCardSignature() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		try {
			CardChannel cardChannel = pcscEid.getCardChannel();
			CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
					new byte[] { 0x04, // length of following data
							(byte) 0x80, // algo ref
							0x01, // rsa pkcs#1
							(byte) 0x84, // tag for private key ref
							(byte) 0x81 });
			ResponseAPDU responseApdu = cardChannel.transmit(setApdu);
			if (0x9000 != responseApdu.getSW()) {
				throw new RuntimeException("SELECT error");
			}

			byte[] message = "hello world".getBytes();
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
			byte[] digestValue = messageDigest.digest(message);

			ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
			digestInfo.write(Constants.SHA1_DIGEST_INFO_PREFIX);
			digestInfo.write(digestValue);
			CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00,
					0x2A, 0x9E, 0x9A, digestInfo.toByteArray());
			responseApdu = cardChannel.transmit(computeDigitalSignatureApdu);
			if (0x9000 != responseApdu.getSW()) {
				throw new RuntimeException("error CDS: "
						+ Integer.toHexString(responseApdu.getSW()));
			}

		} finally {
			pcscEid.close();
		}
	}

	@Test
	public void logoff() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		pcscEidSpi.logoff();

		pcscEidSpi.close();
	}

	@Test
	public void signWhatever() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		CardChannel cardChannel = pcscEid.getCardChannel();

		CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
				new byte[] { 0x04, // length of following data
						(byte) 0x80, // algo ref
						0x01, // rsa pkcs#1
						(byte) 0x84, // tag for private key ref
						(byte) 0x82 }); // auth key
		ResponseAPDU responseApdu = cardChannel.transmit(setApdu);
		assertEquals(0x9000, responseApdu.getSW());

		pcscEid.verifyPin();

		// CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
		// 0x9E, 0x9A, new byte[] {
		// 0x30, // DER
		// 0x1f, // length
		// 0x30, // DER
		// 0x07, // length
		// // OID = SHA1
		// 0x06, // OID tag
		// 0x05, 0x2b, 0x0e, 0x03,
		// 0x02,
		// 0x1a,
		// 0x04, // tag OCTET STRING
		// 0x14, // length
		// 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		// 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
		// 0x13, 0x14 });

		// CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
		// 0x9E, 0x9A, new byte[] {
		// 0x30, // DER DigestInfo
		// 0x18, // length
		// 0x30, // DER AlgorithmIdentifier
		// 0x00, // length: no OID
		// 0x04, // tag OCTET STRING
		// 0x14, // length
		// 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		// 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
		// 0x13, 0x14 });

		CommandAPDU computeDigitalSignatureApdu = new CommandAPDU(0x00, 0x2A,
				0x9E, 0x9A, "Hello world encrypted".getBytes());

		responseApdu = cardChannel.transmit(computeDigitalSignatureApdu);
		assertEquals(0x9000, responseApdu.getSW());
		byte[] signatureValue = responseApdu.getData();
		LOG.debug("signature value size: " + signatureValue.length);

		List<X509Certificate> authnCertChain = pcscEid
				.getAuthnCertificateChain();

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, authnCertChain.get(0).getPublicKey());
		byte[] decryptedSignatureValue = cipher.doFinal(signatureValue);
		LOG.debug("decrypted signature value: "
				+ new String(decryptedSignatureValue));

		pcscEid.close();
	}

	@Test
	public void logoffAndDie() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		try {
			do {
				pcscEidSpi.logoff();
			} while (true);
		} finally {
			pcscEidSpi.close();
		}
	}

	@Test
	public void pcscChangePin() throws Exception {
		this.messages = new Messages(Locale.GERMAN);
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		// PPDU test
		pcscEidSpi.addPPDUName("digipass 870");

		pcscEidSpi.changePin();

		pcscEidSpi.close();
	}

	@Test
	public void pcscUnblockPin() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		// PPDU test
		pcscEidSpi.addPPDUName("digipass 870");

		pcscEidSpi.unblockPin();

		pcscEidSpi.close();
	}

	@Test
	public void photo() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		long t0 = System.currentTimeMillis();
		// pcscEidSpi.selectBelpicJavaCardApplet();
		byte[] photo = pcscEidSpi.readFile(PcscEid.PHOTO_FILE_ID);
		long t1 = System.currentTimeMillis();
		LOG.debug("image size: " + photo.length);
		BufferedImage image = ImageIO.read(new ByteArrayInputStream(photo));
		assertNotNull(image);
		LOG.debug("width: " + image.getWidth());
		LOG.debug("height: " + image.getHeight());
		LOG.debug("dt: " + (t1 - t0) + " ms");

		pcscEidSpi.close();
	}

	@Test
	public void testReadPhoto() throws Exception {
		TerminalFactory terminalFactory = TerminalFactory.getDefault();
		CardTerminals cardTerminals = terminalFactory.terminals();
		CardTerminal cardTerminal = cardTerminals.list().get(0);
		Card card = cardTerminal.connect("T=0");
		CardChannel cardChannel = card.getBasicChannel();
		// select file
		cardChannel.transmit(new CommandAPDU(0x00, 0xA4, 0x08, 0x0C,
				new byte[] { 0x3F, 0x00, (byte) 0xDF, 0x01, 0x40, 0x35 }));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int offset = 0;
		ResponseAPDU responseApdu;
		do {
			// read binary
			responseApdu = cardChannel.transmit(new CommandAPDU(0x00, 0xB0,
					offset >> 8, offset & 0xFF, 0xff));
			baos.write(responseApdu.getData());
			offset += responseApdu.getData().length;
		} while (responseApdu.getData().length == 0xff);
		BufferedImage photo = ImageIO.read(new ByteArrayInputStream(baos
				.toByteArray()));
		JOptionPane.showMessageDialog(null, new ImageIcon(photo));
	}

	@Test
	public void testReadAddress() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		pcscEidSpi.readFile(PcscEid.IDENTITY_FILE_ID);
		byte[] addressFile = pcscEidSpi.readFile(PcscEid.ADDRESS_FILE_ID);
		pcscEidSpi.selectBelpicJavaCardApplet();

		pcscEidSpi.close();

		Address address = TlvParser.parse(addressFile, Address.class);
		LOG.debug("street and number: " + address.getStreetAndNumber());
		LOG.debug("zip: " + address.getZip());
		LOG.debug("municipality: " + address.getMunicipality());
	}

	@Test
	public void testReadNonRepudiationCertificate() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		File tmpFile = File.createTempFile("eid-sign-cert-", ".der");
		byte[] signCert = pcscEidSpi.readFile(PcscEid.SIGN_CERT_FILE_ID);
		FileUtils.writeByteArrayToFile(tmpFile, signCert);

		LOG.debug("ASN1 dump: "
				+ ASN1Dump.dumpAsString(new ASN1InputStream(signCert)
						.readObject()));

		LOG.debug("tmp file: " + tmpFile.getAbsolutePath());

		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(signCert));
		X509Principal issuerPrincipal = PrincipalUtil
				.getIssuerX509Principal(certificate);
		LOG.debug("BC issuer principal: " + issuerPrincipal.getName());
		LOG.debug("Sun issuer (getName): "
				+ certificate.getIssuerX500Principal().getName());
		LOG.debug("Sun issuer (toString): "
				+ certificate.getIssuerX500Principal());
		String issuerName = PrincipalUtil.getIssuerX509Principal(certificate)
				.getName().replace(",", ", ");
		LOG.debug("issuer name: " + issuerName);
		LOG.debug("certificate: " + certificate);

		pcscEidSpi.close();
	}

	@Test
	public void testDEREncoding() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		try {
			byte[] authnCert = pcscEidSpi.readFile(PcscEid.AUTHN_CERT_FILE_ID);
			DERSequence sequence = (DERSequence) new ASN1InputStream(
					new ByteArrayInputStream(authnCert)).readObject();
			String str = ASN1Dump.dumpAsString(sequence);
			LOG.debug(str);
		} finally {
			pcscEidSpi.close();
		}
	}

	private void selectCardManager(CardChannel cardChannel) {
		CommandAPDU selectApplicationApdu = new CommandAPDU(0x00, 0xA4, 0x04,
				0x00);
		ResponseAPDU responseApdu;
		try {
			responseApdu = cardChannel.transmit(selectApplicationApdu);
		} catch (CardException e) {
			LOG.debug("error selecting application");
			return;
		} catch (ArrayIndexOutOfBoundsException e) {
			LOG.debug("array error");
			return;
		}
		if (0x9000 != responseApdu.getSW()) {
			LOG.debug("could not select application");
		} else {
			LOG.debug("application selected");
		}
	}

	@Test
	public void testSelectBelpic() throws Exception {
		final PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		try {
			pcscEid.selectBelpicJavaCardApplet();
		} finally {
			pcscEid.close();
		}
	}

	/**
	 * @throws Exception
	 */
	@Test
	public void testRetrievePIN() throws Exception {
		final PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		byte[] puk12 = new byte[] { 0x22, 0x22, 0x22, 0x11, 0x11, 0x11 };

		try {
			CardChannel cardChannel = pcscEid.getCardChannel();
			for (int pin = 9999; pin >= 0; pin--) {
				LOG.debug("trying PIN: " + pin);
				byte[] bcdPin = new byte[2];
				int dec = pin;
				bcdPin[1] = (byte) (dec % 10);
				dec /= 10;
				bcdPin[1] |= (byte) (dec % 10) << 4;
				dec /= 10;
				bcdPin[0] = (byte) (dec % 10);
				dec /= 10;
				bcdPin[0] |= (byte) (dec % 10) << 4;
				ResponseAPDU responseApdu = verifyPin(bcdPin, cardChannel);
				int sw = responseApdu.getSW();
				if (0x9000 == sw) {
					LOG.debug("PIN is: " + pin);
					break;
				}
				if (0x6983 == sw) {
					unblockPin(puk12, cardChannel);
				}
			}
		} finally {
			pcscEid.close();
		}
	}

	private void unblockPin(byte[] puk12, CardChannel cardChannel)
			throws CardException {
		byte[] unblockPinData = new byte[] { 0x2C, puk12[0], puk12[1],
				puk12[2], puk12[3], puk12[4], puk12[5], (byte) 0xFF };

		CommandAPDU changePinApdu = new CommandAPDU(0x00, 0x2C, 0x00, 0x01,
				unblockPinData);
		ResponseAPDU responseApdu = cardChannel.transmit(changePinApdu);
		if (0x9000 != responseApdu.getSW()) {
			throw new RuntimeException("could not unblock PIN code");
		}
	}

	private ResponseAPDU verifyPin(byte[] pin, CardChannel cardChannel)
			throws CardException {
		byte[] verifyData = new byte[] { 0x24, pin[0], pin[1], (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

		CommandAPDU verifyApdu = new CommandAPDU(0x00, 0x20, 0x00, 0x01,
				verifyData);
		ResponseAPDU responseApdu = cardChannel.transmit(verifyApdu);
		return responseApdu;
	}

	@Test
	public void testCardManager() throws Exception {
		final PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		View view = new TestView();

		CardChannel cardChannel = pcscEid.getCardChannel();
		selectCardManager(cardChannel);
		// card manager active

		TaskRunner taskRunner = new TaskRunner(pcscEid, view);
		try {
			byte[] data = taskRunner.run(new Task<byte[]>() {
				public byte[] run() throws Exception {
					return pcscEid.readFile(PcscEid.IDENTITY_FILE_ID);
				}
			});
			assertNotNull(data);
		} finally {
			pcscEid.close();
		}
	}

	@Test
	public void displayCitizenCertificates() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		byte[] authnCertData = pcscEidSpi.readFile(PcscEid.AUTHN_CERT_FILE_ID);
		byte[] signCertData = pcscEidSpi.readFile(PcscEid.SIGN_CERT_FILE_ID);
		byte[] citizenCaCertData = pcscEidSpi.readFile(PcscEid.CA_CERT_FILE_ID);
		byte[] rootCaCertData = pcscEidSpi.readFile(PcscEid.ROOT_CERT_FILE_ID);
		byte[] nationalRegitryCertData = pcscEidSpi
				.readFile(PcscEid.RRN_CERT_FILE_ID);

		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate authnCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(authnCertData));
		X509Certificate signCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(signCertData));
		X509Certificate citizenCaCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(citizenCaCertData));
		X509Certificate rootCaCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(rootCaCertData));
		X509Certificate nationalRegitryCert = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						nationalRegitryCertData));

		LOG.debug("authentication certificate: " + authnCert);
		LOG.debug("signature certificate: " + signCert);
		LOG.debug("national registry certificate: " + nationalRegitryCert);
		LOG.debug("authn cert size: " + authnCertData.length);
		LOG.debug("sign cert size: " + signCertData.length);
		LOG.debug("citizen CA certificate: " + citizenCaCert);
		LOG.debug("root CA certificate: " + rootCaCert);
		LOG.debug("authn cert serial number: " + authnCert.getSerialNumber());
		LOG.debug("authn certificate issuer: "
				+ authnCert.getIssuerX500Principal());

		File rootCaFile = File.createTempFile("test-root-ca-", ".pem");
		FileWriter rootCaFileWriter = new FileWriter(rootCaFile);
		PEMWriter rootCaPemWriter = new PEMWriter(rootCaFileWriter);
		rootCaPemWriter.writeObject(rootCaCert);
		rootCaPemWriter.close();

		File citizenCaFile = File.createTempFile("test-citizen-ca-", ".pem");
		FileWriter citizenCaFileWriter = new FileWriter(citizenCaFile);
		PEMWriter citizenCaPemWriter = new PEMWriter(citizenCaFileWriter);
		citizenCaPemWriter.writeObject(citizenCaCert);
		citizenCaPemWriter.close();

		pcscEidSpi.close();
		LOG.debug("root ca file: " + rootCaFile.getAbsolutePath());
		LOG.debug("citizen CA file: " + citizenCaFile.getAbsolutePath());
	}

	@Test
	public void testReadIdentityFile() throws Exception {
		PcscEid pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}
		byte[] identityFile;
		File tmpIdentitySignatureFile;
		File tmpRRNCertFile;
		File tmpPhotoFile;
		File tmpAddressFile;
		File tmpAddressSignatureFile;
		try {
			identityFile = pcscEidSpi.readFile(PcscEid.IDENTITY_FILE_ID);
			byte[] identitySignatureData = pcscEidSpi
					.readFile(PcscEid.IDENTITY_SIGN_FILE_ID);
			tmpIdentitySignatureFile = File.createTempFile("identity-sign-",
					".der");
			FileUtils.writeByteArrayToFile(tmpIdentitySignatureFile,
					identitySignatureData);
			byte[] rrnCertData = pcscEidSpi.readFile(PcscEid.RRN_CERT_FILE_ID);
			tmpRRNCertFile = File.createTempFile("rrn-cert-", ".der");
			FileUtils.writeByteArrayToFile(tmpRRNCertFile, rrnCertData);

			tmpPhotoFile = File.createTempFile("test-photo-", ".jpg");
			FileUtils.writeByteArrayToFile(tmpPhotoFile,
					pcscEidSpi.readFile(PcscEid.PHOTO_FILE_ID));

			tmpAddressFile = File.createTempFile("test-address-", ".tlv");
			FileUtils.writeByteArrayToFile(tmpAddressFile,
					pcscEidSpi.readFile(PcscEid.ADDRESS_FILE_ID));

			tmpAddressSignatureFile = File.createTempFile("test-address-sign-",
					".der");
			FileUtils.writeByteArrayToFile(tmpAddressSignatureFile,
					pcscEidSpi.readFile(PcscEid.ADDRESS_SIGN_FILE_ID));
		} finally {
			pcscEidSpi.close();
		}
		LOG.debug("identity file size: " + identityFile.length);
		File tmpIdentityFile = File.createTempFile("identity-", ".tlv");
		FileUtils.writeByteArrayToFile(tmpIdentityFile, identityFile);
		Identity identity = TlvParser.parse(identityFile, Identity.class);
		LOG.debug("DoB: " + identity.getDateOfBirth().getTime());
		LOG.debug("document type: " + identity.getDocumentType());
		LOG.debug("noble condition: " + identity.getNobleCondition());
		LOG.debug("special status: " + identity.getSpecialStatus());
		LOG.debug("duplicate: " + identity.getDuplicate());
		LOG.debug("tmp identity file: " + tmpIdentityFile.getAbsolutePath());
		LOG.debug("tmp identity signature file: "
				+ tmpIdentitySignatureFile.getAbsolutePath());
		LOG.debug("tmp RRN cert file: " + tmpRRNCertFile.getAbsolutePath());
		LOG.debug("tmp photo file: " + tmpPhotoFile.getAbsolutePath());
		LOG.debug("tmp address file: " + tmpAddressFile.getAbsolutePath());
		LOG.debug("tmp address signature file: "
				+ tmpAddressSignatureFile.getAbsolutePath());
	}

	@Test
	public void testCardDataFile() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		try {
			CardChannel cardChannel = pcscEid.getCardChannel();

			while (true) {
				CommandAPDU getCardApdu = new CommandAPDU(0x80, 0xe4, 0x00,
						0x00, 0x1c); // Le = 0x1c
				ResponseAPDU responseApdu = cardChannel.transmit(getCardApdu);
				if (0x9000 != responseApdu.getSW()) {
					fail("SW error: "
							+ Integer.toHexString(responseApdu.getSW()));
				}
				LOG.debug(Hex.encodeHexString(responseApdu.getData()));
			}
		} finally {
			pcscEid.close();
		}
	}

	@Test
	public void testGetChallenge() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		CardChannel cardChannel = pcscEid.getCardChannel();

		int size = 256;
		CommandAPDU getChallengeApdu = new CommandAPDU(0x00, 0x84, 0x00, 0x00,
				new byte[] {}, 0, 0, size);
		ResponseAPDU responseApdu;
		responseApdu = cardChannel.transmit(getChallengeApdu);
		if (0x9000 != responseApdu.getSW()) {
			fail("get challenge failure: "
					+ Integer.toHexString(responseApdu.getSW()));
		}
		LOG.debug("challenge: " + Hex.encodeHexString(responseApdu.getData()));
		assertEquals(size, responseApdu.getData().length);

		pcscEid.close();
	}

	@Test
	public void testGetChallengePcscEid() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		int size = 20;
		byte[] result = pcscEid.getChallenge(size);
		assertEquals(size, result.length);

		pcscEid.close();
	}

	/**
	 * Looking for a clean way to detect PPDU smart card readers.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testDetectPPDU() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		Card card = pcscEid.getCard();
		int ioctl;
		String osName = System.getProperty("os.name");
		if (osName.startsWith("Windows")) {
			ioctl = (0x31 << 16 | (3400) << 2);
		} else {
			ioctl = 0x42000D48;
		}
		byte[] features = card.transmitControlCommand(ioctl, new byte[0]);
		if (0 == features.length) {
			LOG.debug("no CCID reader");
			return;
		}
		LOG.debug("feature list: " + new String(Hex.encodeHex(features)));
		CCIDFeatures ccidFeatures = new CCIDFeatures(features);
		for (int idx = 0; idx < 0x14; idx++) {
			LOG.debug("has feature " + Integer.toHexString(idx) + " "
					+ ccidFeatures.findFeature((byte) idx));
		}
		if (null != ccidFeatures.findFeature((byte) 0x12)) {
			byte[] tlvFeatures = card.transmitControlCommand(
					ccidFeatures.findFeature((byte) 0x12), new byte[0]);
			LOG.debug("TLV feature list: "
					+ new String(Hex.encodeHex(tlvFeatures)));
			FeatureGetTlvProperties featureGetTlvProperties = TlvParser.parse(
					tlvFeatures, FeatureGetTlvProperties.class);
			if (null != featureGetTlvProperties.bPPDUSupport) {
				LOG.debug("PPDU support: "
						+ featureGetTlvProperties.bPPDUSupport[0]);
			}
			if (null != featureGetTlvProperties.usbVendorId) {
				LOG.debug("USB vendor id: "
						+ Hex.encodeHexString(featureGetTlvProperties.usbVendorId));
			}
			if (null != featureGetTlvProperties.usbProductId) {
				LOG.debug("USB product id: "
						+ Hex.encodeHexString(featureGetTlvProperties.usbProductId));
			}
		}
	}

	public static class FeatureGetTlvProperties {
		@TlvField(9)
		public byte[] bPPDUSupport;

		@TlvField(0x0b)
		public byte[] usbVendorId;

		@TlvField(0x0c)
		public byte[] usbProductId;
	}

	private static class CCIDFeatures {
		private final byte[] features;

		public CCIDFeatures(byte[] features) {
			this.features = features;
		}

		public Integer findFeature(byte featureTag) {
			if (null == this.features) {
				return null;
			}
			int idx = 0;
			while (idx < this.features.length) {
				byte tag = this.features[idx];
				idx++;
				idx++;
				if (featureTag == tag) {
					int feature = 0;
					for (int count = 0; count < 3; count++) {
						feature |= this.features[idx] & 0xff;
						idx++;
						feature <<= 8;
					}
					feature |= this.features[idx] & 0xff;
					return feature;
				}
				idx += 4;
			}
			return null;
		}
	}

	@Test
	public void testCcid() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		Card card = pcscEid.getCard();
		// GET FEATURE LIST
		byte[] features = card.transmitControlCommand(0x42000D48, new byte[0]);
		if (0 == features.length) {
			LOG.debug("no CCID reader");
			return;
		}
		LOG.debug("feature list: " + new String(Hex.encodeHex(features)));
		LOG.debug("feature verify pin direct: "
				+ hasFeature(FEATURE_VERIFY_PIN_DIRECT_TAG, features));
		Integer verifyPinControl = findFeature(FEATURE_VERIFY_PIN_DIRECT_TAG,
				features);
		LOG.debug("VERIFY PIN control: 0x"
				+ Integer.toHexString(verifyPinControl));

		CardChannel cardChannel = pcscEid.getCardChannel();
		CommandAPDU setApdu = new CommandAPDU(0x00, 0x22, 0x41, 0xB6,
				new byte[] { 0x04, // length of following data
						(byte) 0x80, // algo ref
						0x01, // rsa pkcs#1
						(byte) 0x84, // tag for private key ref
						(byte) 0x82 });
		ResponseAPDU responseApdu = cardChannel.transmit(setApdu);
		if (0x9000 != responseApdu.getSW()) {
			throw new RuntimeException("SELECT error");
		}

		byte[] verifyCommandData = createPINVerificationDataStructure();

		byte[] result = card.transmitControlCommand(verifyPinControl,
				verifyCommandData);
		responseApdu = new ResponseAPDU(result);
		LOG.debug("status work: " + Integer.toHexString(responseApdu.getSW()));
		if (0x9000 == responseApdu.getSW()) {
			LOG.debug("status OK");
		} else if (0x6401 == responseApdu.getSW()) {
			LOG.debug("canceled by user");
		} else if (0x6400 == responseApdu.getSW()) {
			LOG.debug("timeout");
		}
		/*
		 * The other SW values are those from the VERIFY APDU itself.
		 */
	}

	private byte[] createPINVerificationDataStructure() throws IOException {
		ByteArrayOutputStream verifyCommand = new ByteArrayOutputStream();
		verifyCommand.write(30); // bTimeOut
		verifyCommand.write(30); // bTimeOut2
		verifyCommand.write(0x89); // bmFormatString
		/*
		 * bmFormatString. bit 7: 1 = system units are bytes
		 * 
		 * bit 6-3: 1 = PIN position in APDU command after Lc, so just after the
		 * 0x20.
		 * 
		 * bit 2: 0 = left justify data
		 * 
		 * bit 1-0: 1 = BCD
		 */
		verifyCommand.write(0x47); // bmPINBlockString
		/*
		 * bmPINBlockString
		 * 
		 * bit 7-4: 4 = PIN length
		 * 
		 * bit 3-0: 7 = PIN block size (7 times 0xff)
		 */
		verifyCommand.write(0x04); // bmPINLengthFormat
		/*
		 * bmPINLengthFormat. weird... the values do not make any sense to me.
		 * 
		 * bit 7-5: 0 = RFU
		 * 
		 * bit 4: 0 = system units are bits
		 * 
		 * bit 3-0: 4 = PIN length position in APDU
		 */
		verifyCommand.write(new byte[] { 0x04, 0x04 }); // wPINMaxExtraDigit
		/*
		 * 0x04 = minimum PIN size in digit
		 * 
		 * 0x04 = maximum PIN size in digit. This was 0x0C
		 */
		verifyCommand.write(0x02); // bEntryValidationCondition
		/*
		 * 0x02 = validation key pressed. So the user must press the green
		 * button on his pinpad.
		 */
		verifyCommand.write(0x01); // bNumberMessage
		/*
		 * 0x01 = message with index in bMsgIndex
		 */
		verifyCommand.write(new byte[] { 0x13, 0x08 }); // wLangId
		/*
		 * 0x13, 0x08 = ?
		 */
		verifyCommand.write(0x00); // bMsgIndex
		/*
		 * 0x00 = PIN insertion prompt
		 */
		verifyCommand.write(new byte[] { 0x00, 0x00, 0x00 }); // bTeoPrologue
		/*
		 * bTeoPrologue : only significant for T=1 protocol.
		 */
		byte[] verifyApdu = new byte[] {
				0x00, // CLA
				0x20, // INS
				0x00, // P1
				0x01, // P2
				0x08, // Lc = 8 bytes in command data
				0x20, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
		verifyCommand.write(verifyApdu.length & 0xff); // ulDataLength[0]
		verifyCommand.write(0x00); // ulDataLength[1]
		verifyCommand.write(0x00); // ulDataLength[2]
		verifyCommand.write(0x00); // ulDataLength[3]
		verifyCommand.write(verifyApdu); // abData
		byte[] verifyCommandData = verifyCommand.toByteArray();
		return verifyCommandData;
	}

	public static final byte FEATURE_VERIFY_PIN_DIRECT_TAG = 0x06;

	private boolean hasFeature(byte featureTag, byte[] features) {
		int idx = 0;
		while (idx < features.length) {
			byte tag = features[idx];
			if (featureTag == tag) {
				return true;
			}
			idx += 1 + 1 + 4;
		}
		return false;
	}

	private Integer findFeature(byte featureTag, byte[] features) {
		int idx = 0;
		while (idx < features.length) {
			byte tag = features[idx];
			idx++;
			idx++;
			if (featureTag == tag) {
				int feature = 0;
				for (int count = 0; count < 3; count++) {
					feature |= features[idx] & 0xff;
					idx++;
					feature <<= 8;
				}
				feature |= features[idx] & 0xff;
				return feature;
			}
			idx += 4;
		}
		return null;
	}

	@Test
	public void testListReaders() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		LOG.debug("reader list: " + pcscEid.getReaderList());
	}

	@Test
	public void testBeIDPKIValidation() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		try {
			List<X509Certificate> certChain = pcscEid.getSignCertificateChain();
			LOG.debug("certificate: " + certChain.get(0));

			NetworkConfig networkConfig = new NetworkConfig(
					"proxy.yourict.net", 8080);
			TrustValidator trustValidator = BelgianTrustValidatorFactory
					.createNonRepudiationTrustValidator(networkConfig);

			trustValidator.isTrusted(certChain);
		} finally {
			pcscEid.close();
		}
	}

	@Test
	public void testBeIDPKIValidationCRLOnly() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		List<X509Certificate> certChain;
		try {
			certChain = pcscEid.getSignCertificateChain();
		} finally {
			pcscEid.close();
		}
		LOG.debug("certificate: " + certChain.get(0));

		NetworkConfig networkConfig = new NetworkConfig("proxy.yourict.net",
				8080);

		MemoryCertificateRepository memoryCertificateRepository = new MemoryCertificateRepository();
		X509Certificate rootCaCertificate = loadCertificate("be/fedict/trust/belgiumrca.crt");
		memoryCertificateRepository.addTrustPoint(rootCaCertificate);
		X509Certificate rootCa2Certificate = loadCertificate("be/fedict/trust/belgiumrca2.crt");
		memoryCertificateRepository.addTrustPoint(rootCa2Certificate);

		RevocationData revocationData = new RevocationData();
		TrustValidator trustValidator = new TrustValidator(
				memoryCertificateRepository);
		trustValidator.setRevocationData(revocationData);

		trustValidator.addTrustLinker(new PublicKeyTrustLinker());
		OnlineCrlRepository crlRepository = new OnlineCrlRepository(
				networkConfig);
		trustValidator.addTrustLinker(new CrlTrustLinker(crlRepository));

		try {
			trustValidator.isTrusted(certChain);
		} catch (Exception e) {
			LOG.warn("error: " + e.getMessage());
		}

		byte[] crlData = revocationData.getCrlRevocationData().get(1).getData();
		CertificateList certificateList = CertificateList
				.getInstance(new ASN1InputStream(crlData).readObject());
		X509Extensions crlExtensions = certificateList.getTBSCertList()
				.getExtensions();
		Enumeration<DERObjectIdentifier> oids = crlExtensions.oids();
		while (oids.hasMoreElements()) {
			LOG.debug("oid type: " + oids.nextElement().getId());
		}
	}

	@Test
	public void testPKIValidation() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		try {
			List<X509Certificate> certChain = pcscEid.getSignCertificateChain();
			for (X509Certificate cert : certChain) {
				LOG.debug("certificate: " + cert);
			}

			MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
			certificateRepository
					.addTrustPoint(certChain.get(certChain.size() - 1));

			TrustValidator trustValidator = new TrustValidator(
					certificateRepository);
			trustValidator.addTrustLinker(new PublicKeyTrustLinker());

			NetworkConfig networkConfig = new NetworkConfig(
					"proxy.yourict.net", 8080);

			OnlineOcspRepository ocspRepository = new OnlineOcspRepository(
					networkConfig);

			OnlineCrlRepository crlRepository = new OnlineCrlRepository(
					networkConfig);
			CachedCrlRepository cachedCrlRepository = new CachedCrlRepository(
					crlRepository);

			FallbackTrustLinker fallbackTrustLinker = new FallbackTrustLinker();
			fallbackTrustLinker.addTrustLinker(new OcspTrustLinker(
					ocspRepository));
			fallbackTrustLinker.addTrustLinker(new CrlTrustLinker(
					cachedCrlRepository));

			trustValidator.addTrustLinker(fallbackTrustLinker);

			trustValidator.isTrusted(certChain);
		} finally {
			pcscEid.close();
		}
	}

	private static X509Certificate loadCertificate(String resourceName) {
		LOG.debug("loading certificate: " + resourceName);
		Thread currentThread = Thread.currentThread();
		ClassLoader classLoader = currentThread.getContextClassLoader();
		InputStream certificateInputStream = classLoader
				.getResourceAsStream(resourceName);
		if (null == certificateInputStream) {
			throw new IllegalArgumentException("resource not found: "
					+ resourceName);
		}
		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(certificateInputStream);
			return certificate;
		} catch (CertificateException e) {
			throw new RuntimeException("X509 error: " + e.getMessage(), e);
		}
	}
}
