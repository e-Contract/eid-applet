/*
 * eID Applet Project.
 * Copyright (C) 2009-2010 FedICT.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.eid.applet.service.signer.cms.AbstractCMSSignatureService;
import be.fedict.eid.applet.service.spi.DigestInfo;

public class AbstractCMSSignatureServiceTest {

	private static final Log LOG = LogFactory
			.getLog(AbstractCMSSignatureServiceTest.class);

	@BeforeClass
	public static void beforeClass() {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	public class CMSTestSignatureService extends AbstractCMSSignatureService {

		private final byte[] toBeSigned;

		private final String signatureDescription;

		private byte[] cmsSignature;

		public CMSTestSignatureService(byte[] toBeSigned,
				String signatureDescription) {
			this.toBeSigned = toBeSigned;
			this.signatureDescription = signatureDescription;
		}

		@Override
		protected String getSignatureDescription() {
			return this.signatureDescription;
		}

		@Override
		protected byte[] getToBeSigned() {
			return this.toBeSigned;
		}

		@Override
		protected void storeCMSSignature(byte[] cmsSignature) {
			this.cmsSignature = cmsSignature;
		}

		public byte[] getCMSSignature() {
			return this.cmsSignature;
		}
	}

	@Test
	public void testCMSSignature() throws Exception {
		// setup
		byte[] toBeSigned = "hello world".getBytes();
		String signatureDescription = "Test CMS Signature";
		CMSTestSignatureService signatureService = new CMSTestSignatureService(
				toBeSigned, signatureDescription);

		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = PkiTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test", notBefore, notAfter, null, keyPair
				.getPrivate(), true, 0, null, null, new KeyUsage(
				KeyUsage.nonRepudiation));
		List<X509Certificate> signingCertificateChain = new LinkedList<X509Certificate>();
		signingCertificateChain.add(certificate);

		// operate
		DigestInfo digestInfo = signatureService.preSign(null,
				signingCertificateChain, null, null, null);

		// verify
		assertNotNull(digestInfo);
		byte[] digestValue = digestInfo.digestValue;
		LOG.debug("digest value: " + Hex.encodeHexString(digestValue));
		assertNotNull(digestValue);
		assertEquals(signatureDescription, digestInfo.description);
		assertEquals("SHA1", digestInfo.digestAlgo);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(
				PkiTestUtils.SHA1_DIGEST_INFO_PREFIX, digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);
		LOG.debug("signature value: " + Hex.encodeHexString(signatureValue));

		// operate
		signatureService.postSign(signatureValue, signingCertificateChain);

		// verify
		byte[] cmsSignature = signatureService.getCMSSignature();
		CMSSignedData signedData = new CMSSignedData(cmsSignature);
		SignerInformationStore signers = signedData.getSignerInfos();
		Iterator<SignerInformation> iter = signers.getSigners().iterator();
		while (iter.hasNext()) {
			SignerInformation signer = iter.next();
			SignerId signerId = signer.getSID();
			assertTrue(signerId.match(certificate));
			assertTrue(signer.verify(keyPair.getPublic(),
					BouncyCastleProvider.PROVIDER_NAME));
		}
		byte[] data = (byte[]) signedData.getSignedContent().getContent();
		assertArrayEquals(toBeSigned, data);
	}
}
