/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.crypto.Cipher;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.AbstractODFSignatureService;
import be.fedict.eid.applet.service.signer.KeyInfoKeySelector;
import be.fedict.eid.applet.service.signer.ODFResourceResolverSpi;
import be.fedict.eid.applet.service.signer.ODFURIDereferencer;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.spi.DigestInfo;

public class AbstractODFSignatureServiceTest {

	private static final Log LOG = LogFactory
			.getLog(AbstractODFSignatureServiceTest.class);

	@Before
	public void setUp() throws Exception {
		Init.init();
	}

	@Test
	public void testVerifySignature() throws Exception {
		URL odfUrl = AbstractODFSignatureServiceTest.class
				.getResource("/hello-world-signed.odt");
		assertTrue(hasOdfSignature(odfUrl, 1));
	}

	@Test
	public void testVerifyCoSignature() throws Exception {
		URL odfUrl = AbstractODFSignatureServiceTest.class
				.getResource("/hello-world-signed-twice.odt");
		assertTrue(hasOdfSignature(odfUrl, 2));
	}

	private boolean hasOdfSignature(URL odfUrl, int signatureCount)
			throws IOException, ParserConfigurationException, SAXException,
			org.apache.xml.security.signature.XMLSignatureException,
			XMLSecurityException, MarshalException, XMLSignatureException {
		InputStream odfInputStream = odfUrl.openStream();
		if (null == odfInputStream) {
			return false;
		}
		ZipInputStream odfZipInputStream = new ZipInputStream(odfInputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
			LOG.debug(zipEntry.getName());
			if (true == "META-INF/documentsignatures.xml".equals(zipEntry
					.getName())) {
				Document documentSignatures = loadDocument(odfZipInputStream);
				NodeList signatureNodeList = documentSignatures
						.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
				assertEquals(signatureCount, signatureNodeList.getLength());
				for (int idx = 0; idx < signatureNodeList.getLength(); idx++) {
					Node signatureNode = signatureNodeList.item(idx);
					if (false == verifySignatureApache(odfUrl, signatureNode)) {
						LOG.debug("apache says invalid signature");
						return false;
					}
					if (false == verifySignature(odfUrl, signatureNode)) {
						LOG.debug("JSR105 says invalid signature");
						return false;
					}
				}
				return true;
			}
		}
		LOG.debug("no documentsignatures.xml entry present");
		return false;
	}

	private static class ODFTestSignatureService extends
			AbstractODFSignatureService {

		private URL odfUrl;

		private final TemporaryTestDataStorage temporaryDataStorage;

		private final ByteArrayOutputStream signedODFOutputStream;

		public ODFTestSignatureService() {
			this.temporaryDataStorage = new TemporaryTestDataStorage();
			this.signedODFOutputStream = new ByteArrayOutputStream();
		}

		@Override
		protected URL getOpenDocumentURL() {
			return this.odfUrl;
		}

		public void setOdfUrl(URL odfUrl) {
			this.odfUrl = odfUrl;
		}

		@Override
		protected TemporaryDataStorage getTemporaryDataStorage() {
			return this.temporaryDataStorage;
		}

		public byte[] getSignedODFData() {
			return this.signedODFOutputStream.toByteArray();
		}

		@Override
		protected OutputStream getSignedOpenDocumentOutputStream() {
			return this.signedODFOutputStream;
		}
	}

	@Test
	public void testSign() throws Exception {
		sign("/hello-world.odt", 1);
	}

	@Test
	public void testSignZipEntriesWithSpaces() throws Exception {
		sign("/hello-world-spaces.odt", 1);
	}

	@Test
	public void testCoSign() throws Exception {
		sign("/hello-world-signed.odt", 2);
	}

	private void sign(String resourceName, int signatureCount) throws Exception {
		// setup
		LOG.debug("test sign: " + resourceName);
		URL odfUrl = AbstractODFSignatureServiceTest.class
				.getResource(resourceName);
		assertNotNull(odfUrl);
		ODFTestSignatureService odfSignatureService = new ODFTestSignatureService();
		odfSignatureService.setOdfUrl(odfUrl);

		// operate
		DigestInfo digestInfo = odfSignatureService.preSign(null, null);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("signature description: " + digestInfo.description);
		LOG.debug("signature hash algo: " + digestInfo.digestAlgo);
		assertEquals("ODF Document", digestInfo.description);
		assertEquals("SHA-1", digestInfo.digestAlgo);
		assertNotNull(digestInfo.digestValue);

		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(
				PkiTestUtils.SHA1_DIGEST_INFO_PREFIX, digestInfo.digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = PkiTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test", notBefore, notAfter, null, keyPair
				.getPrivate(), true, 0, null, null, new KeyUsage(
				KeyUsage.nonRepudiation));

		/*
		 * Operate: postSign
		 */
		odfSignatureService.postSign(signatureValue, Collections
				.singletonList(certificate));

		byte[] signedODFData = odfSignatureService.getSignedODFData();
		assertNotNull(signedODFData);
		LOG.debug("signed ODF size: " + signedODFData.length);
		File tmpFile = File.createTempFile("signed-", ".odt");
		FileUtils.writeByteArrayToFile(tmpFile, signedODFData);
		LOG.debug("signed ODF file: " + tmpFile.getAbsolutePath());
		assertTrue(hasOdfSignature(tmpFile.toURI().toURL(), signatureCount));
		LOG.debug("signed ODF file: " + tmpFile.getAbsolutePath());
	}

	private boolean verifySignatureApache(URL odfUrl, Node signatureNode)
			throws org.apache.xml.security.signature.XMLSignatureException,
			XMLSecurityException {
		org.apache.xml.security.signature.XMLSignature xmlSignature = new org.apache.xml.security.signature.XMLSignature(
				(Element) signatureNode, null);
		ResourceResolverSpi resourceResolver = new ODFResourceResolverSpi(
				odfUrl);
		xmlSignature.addResourceResolver(resourceResolver);
		KeyInfo keyInfo = xmlSignature.getKeyInfo();
		X509Certificate certificate = keyInfo.getX509Certificate();
		LOG.debug("cert subject: " + certificate.getSubjectX500Principal());
		boolean validity = xmlSignature.checkSignatureValue(certificate);
		return validity;
	}

	/**
	 * Verification via the default JSR105 implementation triggers some
	 * canonicalization errors.
	 * 
	 * @param odfUrl
	 * @param signatureNode
	 * @throws MarshalException
	 * @throws XMLSignatureException
	 */
	private boolean verifySignature(URL odfUrl, Node signatureNode)
			throws MarshalException, XMLSignatureException {
		DOMValidateContext domValidateContext = new DOMValidateContext(
				new KeyInfoKeySelector(), signatureNode);
		ODFURIDereferencer dereferencer = new ODFURIDereferencer(odfUrl);
		domValidateContext.setURIDereferencer(dereferencer);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		LOG.debug("java version: " + System.getProperty("java.version"));
		/*
		 * Requires Java 6u10 because of a bug. See also:
		 * http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6696582
		 */
		XMLSignature xmlSignature = xmlSignatureFactory
				.unmarshalXMLSignature(domValidateContext);
		boolean validity = xmlSignature.validate(domValidateContext);
		return validity;
	}

	private Document loadDocument(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		InputSource inputSource = new InputSource(documentInputStream);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(inputSource);
		return document;
	}
}
