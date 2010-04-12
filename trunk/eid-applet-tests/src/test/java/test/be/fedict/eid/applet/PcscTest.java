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
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;

import javax.imageio.ImageIO;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.eid.applet.Messages;
import be.fedict.eid.applet.Status;
import be.fedict.eid.applet.View;
import be.fedict.eid.applet.sc.PcscEid;
import be.fedict.eid.applet.sc.PcscEidSpi;
import be.fedict.eid.applet.sc.Pkcs11Eid;
import be.fedict.eid.applet.sc.Task;
import be.fedict.eid.applet.sc.TaskRunner;
import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.FallbackTrustLinker;
import be.fedict.trust.MemoryCertificateRepository;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.PublicKeyTrustLinker;
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

	private static final Log LOG = LogFactory.getLog(PcscTest.class);

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
				boolean includePhoto, String identityDataUsage) {
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
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}
		byte[] challenge = "hello world".getBytes();
		byte[] signatureValue;
		List<X509Certificate> authnCertChain;
		try {
			signatureValue = pcscEid.signAuthn(challenge);
			authnCertChain = pcscEid.getAuthnCertificateChain();
			//pcscEid.logoff();
		} finally {
			pcscEid.close();
		}

		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initVerify(authnCertChain.get(0).getPublicKey());
		signature.update(challenge);
		boolean result = signature.verify(signatureValue);
		assertTrue(result);
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
		LOG.debug("test: " + (true ? "true" : "false"));
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
			digestInfo.write(Pkcs11Eid.SHA1_DIGEST_INFO_PREFIX);
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
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		pcscEidSpi.logoff();

		pcscEidSpi.close();
	}

	@Test
	public void pcscChangePin() throws Exception {
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		pcscEidSpi.changePin();

		pcscEidSpi.close();
	}

	@Test
	public void pcscUnblockPin() throws Exception {
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		pcscEidSpi.unblockPin();

		pcscEidSpi.close();
	}

	@Test
	public void photo() throws Exception {
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		long t0 = System.currentTimeMillis();
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
	public void testReadAddress() throws Exception {
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}

		pcscEidSpi.readFile(PcscEid.IDENTITY_FILE_ID);
		pcscEidSpi.readFile(PcscEid.ADDRESS_FILE_ID);

		pcscEidSpi.close();
	}

	@Test
	public void testDEREncoding() throws Exception {
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
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
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
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
		PcscEidSpi pcscEidSpi = new PcscEid(new TestView(), this.messages);
		if (false == pcscEidSpi.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEidSpi.waitForEidPresent();
		}
		byte[] identityFile;
		try {
			identityFile = pcscEidSpi.readFile(PcscEid.IDENTITY_FILE_ID);
		} finally {
			pcscEidSpi.close();
		}
		LOG.debug("identity file size: " + identityFile.length);
		File tmpIdentityFile = File.createTempFile("identity-", ".tlv");
		LOG.debug("tmp identity file: " + tmpIdentityFile.getAbsolutePath());
		FileUtils.writeByteArrayToFile(tmpIdentityFile, identityFile);
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
	public void testPKIValidation() throws Exception {
		PcscEid pcscEid = new PcscEid(new TestView(), this.messages);
		if (false == pcscEid.isEidPresent()) {
			LOG.debug("insert eID card");
			pcscEid.waitForEidPresent();
		}

		try {
			List<X509Certificate> certChain = pcscEid
					.getAuthnCertificateChain();
			// List<X509Certificate> certChain =
			// pcscEid.getAuthnCertificateChain();
			LOG.debug("end-entity certificate: " + certChain.get(0));

			MemoryCertificateRepository certificateRepository = new MemoryCertificateRepository();
			certificateRepository.addTrustPoint(certChain
					.get(certChain.size() - 1));

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
}
