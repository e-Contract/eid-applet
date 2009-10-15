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

package test.unit.be.fedict.eid.applet.service.signer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.crypto.Cipher;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.fedict.eid.applet.service.signer.AbstractXmlSignatureService;
import be.fedict.eid.applet.service.signer.EnvelopedSignatureFacet;
import be.fedict.eid.applet.service.signer.KeyInfoSignatureFacet;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.signer.XAdESSignatureFacet;
import be.fedict.eid.applet.service.spi.DigestInfo;

public class XAdESSignatureFacetTest {

	private static final Log LOG = LogFactory
			.getLog(XAdESSignatureFacetTest.class);

	private static class XmlSignatureTestService extends
			AbstractXmlSignatureService {

		private TemporaryTestDataStorage temporaryDataStorage;

		private ByteArrayOutputStream signedDocumentOutputStream;

		public XmlSignatureTestService(SignatureFacet... signatureFacets) {
			super();
			this.temporaryDataStorage = new TemporaryTestDataStorage();
			this.signedDocumentOutputStream = new ByteArrayOutputStream();
			for (SignatureFacet signatureFacet : signatureFacets) {
				addSignatureFacet(signatureFacet);
			}
		}

		public byte[] getSignedDocumentData() {
			return this.signedDocumentOutputStream.toByteArray();
		}

		@Override
		protected OutputStream getSignedDocumentOutputStream() {
			return this.signedDocumentOutputStream;
		}

		@Override
		protected TemporaryDataStorage getTemporaryDataStorage() {
			return this.temporaryDataStorage;
		}

		public String getFilesDigestAlgorithm() {
			return null;
		}
	}

	@Test
	public void testSignEnvelopingDocument() throws Exception {
		// setup
		EnvelopedSignatureFacet envelopedSignatureFacet = new EnvelopedSignatureFacet();
		KeyInfoSignatureFacet keyInfoSignatureFacet = new KeyInfoSignatureFacet(
				true, false, false);
		XAdESSignatureFacet xadesSignatureFacet = new XAdESSignatureFacet();
		XmlSignatureTestService testedInstance = new XmlSignatureTestService(
				envelopedSignatureFacet, keyInfoSignatureFacet,
				xadesSignatureFacet);

		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = PkiTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test", notBefore, notAfter, null, keyPair
				.getPrivate(), true, 0, null, null, new KeyUsage(
				KeyUsage.nonRepudiation));

		// operate
		DigestInfo digestInfo = testedInstance.preSign(null, Collections
				.singletonList(certificate));

		// verify
		assertNotNull(digestInfo);
		assertEquals("SHA-1", digestInfo.digestAlgo);
		assertNotNull(digestInfo.digestValue);

		TemporaryTestDataStorage temporaryDataStorage = (TemporaryTestDataStorage) testedInstance
				.getTemporaryDataStorage();
		assertNotNull(temporaryDataStorage);
		InputStream tempInputStream = temporaryDataStorage.getTempInputStream();
		assertNotNull(tempInputStream);
		Document tmpDocument = PkiTestUtils.loadDocument(tempInputStream);

		LOG.debug("tmp document: " + PkiTestUtils.toString(tmpDocument));
		Element nsElement = tmpDocument.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades",
				"http://uri.etsi.org/01903/v1.3.2#");
		Node digestValueNode = XPathAPI.selectSingleNode(tmpDocument,
				"//ds:DigestValue", nsElement);
		assertNotNull(digestValueNode);
		String digestValueTextContent = digestValueNode.getTextContent();
		LOG.debug("digest value text content: " + digestValueTextContent);
		assertFalse(digestValueTextContent.isEmpty());

		/*
		 * Sign the received XML signature digest value.
		 */
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(
				PkiTestUtils.SHA1_DIGEST_INFO_PREFIX, digestInfo.digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		/*
		 * Operate: postSign
		 */
		testedInstance.postSign(signatureValue, Collections
				.singletonList(certificate));

		byte[] signedDocumentData = testedInstance.getSignedDocumentData();
		assertNotNull(signedDocumentData);
		Document signedDocument = PkiTestUtils
				.loadDocument(new ByteArrayInputStream(signedDocumentData));
		LOG.debug("signed document: " + PkiTestUtils.toString(signedDocument));

		NodeList signatureNodeList = signedDocument.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Node signatureNode = signatureNodeList.item(0);

		DOMValidateContext domValidateContext = new DOMValidateContext(
				KeySelector.singletonKeySelector(keyPair.getPublic()),
				signatureNode);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		XMLSignature xmlSignature = xmlSignatureFactory
				.unmarshalXMLSignature(domValidateContext);
		boolean validity = xmlSignature.validate(domValidateContext);
		assertTrue(validity);

		File tmpFile = File.createTempFile("xades-bes-", ".xml");
		FileUtils.writeStringToFile(tmpFile, PkiTestUtils
				.toString(signedDocument));
		LOG.debug("tmp file: " + tmpFile.getAbsolutePath());

		Node resultNode = XPathAPI
				.selectSingleNode(
						signedDocument,
						"ds:Signature/ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert/xades:CertDigest/ds:DigestValue",
						nsElement);
		assertNotNull(resultNode);
	}
}
