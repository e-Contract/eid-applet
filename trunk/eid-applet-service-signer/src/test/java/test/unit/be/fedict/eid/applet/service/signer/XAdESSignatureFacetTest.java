/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.OCSPResp;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

import be.fedict.eid.applet.service.signer.AbstractXmlSignatureService;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.signer.facets.EnvelopedSignatureFacet;
import be.fedict.eid.applet.service.signer.facets.KeyInfoSignatureFacet;
import be.fedict.eid.applet.service.signer.facets.RevocationData;
import be.fedict.eid.applet.service.signer.facets.RevocationDataService;
import be.fedict.eid.applet.service.signer.facets.TimeStampService;
import be.fedict.eid.applet.service.signer.facets.XAdESSignatureFacet;
import be.fedict.eid.applet.service.signer.facets.XAdESXLSignatureFacet;
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
			setSignatureNamespacePrefix("ds");
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

	@BeforeClass
	public static void beforeClass() {
		if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@Test
	public void testSignEnvelopingDocument() throws Exception {
		// setup
		EnvelopedSignatureFacet envelopedSignatureFacet = new EnvelopedSignatureFacet();
		KeyInfoSignatureFacet keyInfoSignatureFacet = new KeyInfoSignatureFacet(
				true, false, false);
		XAdESSignatureFacet xadesSignatureFacet = new XAdESSignatureFacet();
		TimeStampService mockTimeStampService = EasyMock
				.createMock(TimeStampService.class);
		RevocationDataService mockRevocationDataService = EasyMock
				.createMock(RevocationDataService.class);
		XAdESXLSignatureFacet xadesTSignatureFacet = new XAdESXLSignatureFacet(
				mockTimeStampService, mockRevocationDataService);
		XmlSignatureTestService testedInstance = new XmlSignatureTestService(
				envelopedSignatureFacet, keyInfoSignatureFacet,
				xadesSignatureFacet, xadesTSignatureFacet);

		KeyPair keyPair = PkiTestUtils.generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = PkiTestUtils.generateCertificate(keyPair
				.getPublic(), "CN=Test", notBefore, notAfter, null, keyPair
				.getPrivate(), true, 0, null, null, new KeyUsage(
				KeyUsage.nonRepudiation));
		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		/*
		 * We need at least 2 certificates for the XAdES-C complete certificate
		 * refs construction.
		 */
		certificateChain.add(certificate);
		certificateChain.add(certificate);

		RevocationData revocationData = new RevocationData();
		X509CRL crl = PkiTestUtils.generateCrl(certificate, keyPair
				.getPrivate());
		revocationData.addCRL(crl);
		OCSPResp ocspResp = PkiTestUtils.createOcspResp(certificate, false,
				certificate, certificate, keyPair.getPrivate(), "SHA1withRSA");
		revocationData.addOCSP(ocspResp.getEncoded());

		// expectations
		EasyMock.expect(
				mockTimeStampService
						.timeStamp(EasyMock.anyObject(byte[].class)))
				.andStubReturn("test-time-stamp-token".getBytes());
		EasyMock.expect(
				mockRevocationDataService.getRevocationData(EasyMock
						.eq(certificateChain))).andStubReturn(revocationData);

		// prepare
		EasyMock.replay(mockTimeStampService, mockRevocationDataService);

		// operate
		DigestInfo digestInfo = testedInstance.preSign(null, certificateChain);

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
		testedInstance.postSign(signatureValue, certificateChain);

		// verify
		EasyMock.verify(mockTimeStampService, mockRevocationDataService);
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

		// also test whether the XAdES extension is in line with the XAdES XML
		// Schema.

		// stax-api 1.0.1 prevents us from using
		// "XMLConstants.W3C_XML_SCHEMA_NS_URI"
		Node qualifyingPropertiesNode = XPathAPI.selectSingleNode(
				signedDocument,
				"ds:Signature/ds:Object/xades:QualifyingProperties", nsElement);
		SchemaFactory factory = SchemaFactory
				.newInstance("http://www.w3.org/2001/XMLSchema");
		LSResourceResolver xadesResourceResolver = new XAdESLSResourceResolver();
		factory.setResourceResolver(xadesResourceResolver);
		InputStream schemaInputStream = XAdESSignatureFacetTest.class
				.getResourceAsStream("/XAdESv141.xsd");
		Source schemaSource = new StreamSource(schemaInputStream);
		Schema schema = factory.newSchema(schemaSource);
		Validator validator = schema.newValidator();
		// DOMResult gives some DOMException...
		validator.validate(new DOMSource(qualifyingPropertiesNode));

		StreamSource streamSource = new StreamSource(tmpFile.toURI().toString());
		ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream();
		StreamResult streamResult = new StreamResult(resultOutputStream);
		// validator.validate(streamSource, streamResult);
		LOG.debug("result: " + resultOutputStream);
	}

	private static class XAdESLSResourceResolver implements LSResourceResolver {

		private static final Log LOG = LogFactory
				.getLog(XAdESLSResourceResolver.class);

		public LSInput resolveResource(String type, String namespaceURI,
				String publicId, String systemId, String baseURI) {
			LOG.debug("resolve resource");
			LOG.debug("type: " + type);
			LOG.debug("namespace URI: " + namespaceURI);
			LOG.debug("publicId: " + publicId);
			LOG.debug("systemId: " + systemId);
			LOG.debug("base URI: " + baseURI);
			if ("http://uri.etsi.org/01903/v1.3.2#".equals(namespaceURI)) {
				return new LocalLSInput(publicId, systemId, baseURI,
						"/XAdES.xsd");
			}
			if ("http://www.w3.org/2000/09/xmldsig#".equals(namespaceURI)) {
				return new LocalLSInput(publicId, systemId, baseURI,
						"/xmldsig-core-schema.xsd");
			}
			throw new RuntimeException("unsupported resource: " + namespaceURI);
		}
	}

	private static class LocalLSInput implements LSInput {

		private String publicId;

		private String systemId;

		private String baseURI;

		private final String schemaResourceName;

		public LocalLSInput(String publicId, String systemId, String baseURI,
				String schemaResourceName) {
			this.publicId = publicId;
			this.systemId = systemId;
			this.baseURI = baseURI;
			this.schemaResourceName = schemaResourceName;
		}

		public String getBaseURI() {
			return this.baseURI;
		}

		public InputStream getByteStream() {
			InputStream inputStream = XAdESSignatureFacetTest.class
					.getResourceAsStream(this.schemaResourceName);
			return inputStream;
		}

		public boolean getCertifiedText() {
			return true;
		}

		public Reader getCharacterStream() {
			InputStream inputStream = getByteStream();
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					inputStream));
			return reader;
		}

		public String getEncoding() {
			return "UTF-8";
		}

		public String getPublicId() {
			return this.publicId;
		}

		public String getStringData() {
			InputStream inputStream = getByteStream();
			String stringData;
			try {
				stringData = IOUtils.toString(inputStream);
			} catch (IOException e) {
				throw new RuntimeException("I/O error: " + e.getMessage(), e);
			}
			return stringData;
		}

		public String getSystemId() {
			return this.systemId;
		}

		public void setBaseURI(String baseURI) {
			this.baseURI = baseURI;
		}

		public void setByteStream(InputStream byteStream) {
			throw new UnsupportedOperationException();
		}

		public void setCertifiedText(boolean certifiedText) {
			throw new UnsupportedOperationException();
		}

		public void setCharacterStream(Reader characterStream) {
			throw new UnsupportedOperationException();
		}

		public void setEncoding(String encoding) {
			throw new UnsupportedOperationException();
		}

		public void setPublicId(String publicId) {
			this.publicId = publicId;
		}

		public void setStringData(String stringData) {
			throw new UnsupportedOperationException();
		}

		public void setSystemId(String systemId) {
			this.systemId = systemId;
		}
	}
}
