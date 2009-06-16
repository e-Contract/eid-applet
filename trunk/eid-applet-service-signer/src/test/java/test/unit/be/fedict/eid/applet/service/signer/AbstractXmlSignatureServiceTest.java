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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.jcp.xml.dsig.internal.dom.DOMReference;
import org.jcp.xml.dsig.internal.dom.DOMXMLSignature;
import org.joda.time.DateTime;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.AbstractXmlSignatureService;
import be.fedict.eid.applet.service.signer.TemporaryDataStorage;
import be.fedict.eid.applet.service.spi.DigestInfo;

public class AbstractXmlSignatureServiceTest {

	private static final Log LOG = LogFactory
			.getLog(AbstractXmlSignatureServiceTest.class);

	public static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04,
			0x14 };

	private static class XmlSignatureTestService extends
			AbstractXmlSignatureService {

		private Document envelopingDocument;

		private List<String> referenceIds;

		private TemporaryTestDataStorage temporaryDataStorage;

		private String signatureDescription;

		private ByteArrayOutputStream signedDocumentOutputStream;

		public XmlSignatureTestService() {
			super();
			this.referenceIds = new LinkedList<String>();
			this.temporaryDataStorage = new TemporaryTestDataStorage();
			this.signedDocumentOutputStream = new ByteArrayOutputStream();
		}

		public byte[] getSignedDocumentData() {
			return this.signedDocumentOutputStream.toByteArray();
		}

		public void setEnvelopingDocument(Document envelopingDocument) {
			this.envelopingDocument = envelopingDocument;
		}

		@Override
		protected Document getEnvelopingDocument() {
			return this.envelopingDocument;
		}

		@Override
		protected String getSignatureDescription() {
			return this.signatureDescription;
		}

		public void setSignatureDescription(String signatureDescription) {
			this.signatureDescription = signatureDescription;
		}

		@Override
		protected List<String> getReferenceIds() {
			return this.referenceIds;
		}

		public void addReferenceId(String referenceId) {
			this.referenceIds.add(referenceId);
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

	private static class TemporaryTestDataStorage implements
			TemporaryDataStorage {

		private ByteArrayOutputStream outputStream;

		public TemporaryTestDataStorage() {
			this.outputStream = new ByteArrayOutputStream();
		}

		public InputStream getTempInputStream() {
			byte[] data = this.outputStream.toByteArray();
			ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
			return inputStream;
		}

		public OutputStream getTempOutputStream() {
			return this.outputStream;
		}
	}

	@Test
	public void testSignEnvelopingDocument() throws Exception {
		// setup
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();
		Element rootElement = document.createElementNS("urn:test", "tns:root");
		rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
				"urn:test");
		document.appendChild(rootElement);
		Element dataElement = document.createElementNS("urn:test", "tns:data");
		dataElement.setAttributeNS(null, "Id", "id-1234");
		dataElement.setTextContent("data to be signed");
		rootElement.appendChild(dataElement);

		XmlSignatureTestService testedInstance = new XmlSignatureTestService();
		testedInstance.setEnvelopingDocument(document);
		testedInstance.addReferenceId("id-1234");
		testedInstance.setSignatureDescription("test-signature-description");

		// operate
		DigestInfo digestInfo = testedInstance.preSign(null, null);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("digest info description: " + digestInfo.description);
		assertEquals("test-signature-description", digestInfo.description);
		assertNotNull(digestInfo.digestValue);
		LOG.debug("digest algo: " + digestInfo.digestAlgo);
		assertEquals("SHA-1", digestInfo.digestAlgo);

		TemporaryTestDataStorage temporaryDataStorage = (TemporaryTestDataStorage) testedInstance
				.getTemporaryDataStorage();
		assertNotNull(temporaryDataStorage);
		InputStream tempInputStream = temporaryDataStorage.getTempInputStream();
		assertNotNull(tempInputStream);
		Document tmpDocument = loadDocument(tempInputStream);

		LOG.debug("tmp document: " + toString(tmpDocument));
		Element nsElement = tmpDocument.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		Node digestValueNode = XPathAPI.selectSingleNode(tmpDocument,
				"//ds:DigestValue", nsElement);
		assertNotNull(digestValueNode);
		String digestValueTextContent = digestValueNode.getTextContent();
		LOG.debug("digest value text content: " + digestValueTextContent);
		assertFalse(digestValueTextContent.isEmpty());

		/*
		 * Sign the received XML signature digest value.
		 */
		KeyPair keyPair = generateKeyPair();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(SHA1_DIGEST_INFO_PREFIX,
				digestInfo.digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null, new KeyUsage(KeyUsage.nonRepudiation));

		/*
		 * Operate: postSign
		 */
		testedInstance.postSign(signatureValue, Collections
				.singletonList(certificate));

		byte[] signedDocumentData = testedInstance.getSignedDocumentData();
		assertNotNull(signedDocumentData);
		Document signedDocument = loadDocument(new ByteArrayInputStream(
				signedDocumentData));
		LOG.debug("signed document: " + toString(signedDocument));

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
	}

	@Test
	public void testSignEnvelopingDocumentWithExternalDigestInfo()
			throws Exception {
		// setup
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();
		Element rootElement = document.createElementNS("urn:test", "tns:root");
		rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
				"urn:test");
		document.appendChild(rootElement);

		XmlSignatureTestService testedInstance = new XmlSignatureTestService();
		testedInstance.setEnvelopingDocument(document);
		testedInstance.setSignatureDescription("test-signature-description");

		byte[] refData = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
		messageDigest.update(refData);
		byte[] digestValue = messageDigest.digest();
		DigestInfo refDigestInfo = new DigestInfo(digestValue, "SHA-1",
				"urn:test:ref");

		// operate
		DigestInfo digestInfo = testedInstance.preSign(Collections
				.singletonList(refDigestInfo), null);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("digest info description: " + digestInfo.description);
		assertEquals("test-signature-description", digestInfo.description);
		assertNotNull(digestInfo.digestValue);
		LOG.debug("digest algo: " + digestInfo.digestAlgo);
		assertEquals("SHA-1", digestInfo.digestAlgo);

		TemporaryTestDataStorage temporaryDataStorage = (TemporaryTestDataStorage) testedInstance
				.getTemporaryDataStorage();
		assertNotNull(temporaryDataStorage);
		InputStream tempInputStream = temporaryDataStorage.getTempInputStream();
		assertNotNull(tempInputStream);
		Document tmpDocument = loadDocument(tempInputStream);

		LOG.debug("tmp document: " + toString(tmpDocument));
		Element nsElement = tmpDocument.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		Node digestValueNode = XPathAPI.selectSingleNode(tmpDocument,
				"//ds:DigestValue", nsElement);
		assertNotNull(digestValueNode);
		String digestValueTextContent = digestValueNode.getTextContent();
		LOG.debug("digest value text content: " + digestValueTextContent);
		assertFalse(digestValueTextContent.isEmpty());

		/*
		 * Sign the received XML signature digest value.
		 */
		KeyPair keyPair = generateKeyPair();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(SHA1_DIGEST_INFO_PREFIX,
				digestInfo.digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null, new KeyUsage(KeyUsage.nonRepudiation));

		/*
		 * Operate: postSign
		 */
		testedInstance.postSign(signatureValue, Collections
				.singletonList(certificate));

		byte[] signedDocumentData = testedInstance.getSignedDocumentData();
		assertNotNull(signedDocumentData);
		Document signedDocument = loadDocument(new ByteArrayInputStream(
				signedDocumentData));
		LOG.debug("signed document: " + toString(signedDocument));

		NodeList signatureNodeList = signedDocument.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Node signatureNode = signatureNodeList.item(0);

		DOMValidateContext domValidateContext = new DOMValidateContext(
				KeySelector.singletonKeySelector(keyPair.getPublic()),
				signatureNode);
		URIDereferencer dereferencer = new URITestDereferencer();
		domValidateContext.setURIDereferencer(dereferencer);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		XMLSignature xmlSignature = xmlSignatureFactory
				.unmarshalXMLSignature(domValidateContext);
		boolean validity = xmlSignature.validate(domValidateContext);
		assertTrue(validity);
	}

	@Test
	public void testSignExternalDigestInfo() throws Exception {
		// setup
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();

		XmlSignatureTestService testedInstance = new XmlSignatureTestService();
		testedInstance.setEnvelopingDocument(document);
		testedInstance.setSignatureDescription("test-signature-description");

		byte[] refData = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
		messageDigest.update(refData);
		byte[] digestValue = messageDigest.digest();
		DigestInfo refDigestInfo = new DigestInfo(digestValue, "SHA-1",
				"urn:test:ref");

		// operate
		DigestInfo digestInfo = testedInstance.preSign(Collections
				.singletonList(refDigestInfo), null);

		// verify
		assertNotNull(digestInfo);
		LOG.debug("digest info description: " + digestInfo.description);
		assertEquals("test-signature-description", digestInfo.description);
		assertNotNull(digestInfo.digestValue);
		LOG.debug("digest algo: " + digestInfo.digestAlgo);
		assertEquals("SHA-1", digestInfo.digestAlgo);

		TemporaryTestDataStorage temporaryDataStorage = (TemporaryTestDataStorage) testedInstance
				.getTemporaryDataStorage();
		assertNotNull(temporaryDataStorage);
		InputStream tempInputStream = temporaryDataStorage.getTempInputStream();
		assertNotNull(tempInputStream);
		Document tmpDocument = loadDocument(tempInputStream);

		LOG.debug("tmp document: " + toString(tmpDocument));
		Element nsElement = tmpDocument.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		Node digestValueNode = XPathAPI.selectSingleNode(tmpDocument,
				"//ds:DigestValue", nsElement);
		assertNotNull(digestValueNode);
		String digestValueTextContent = digestValueNode.getTextContent();
		LOG.debug("digest value text content: " + digestValueTextContent);
		assertFalse(digestValueTextContent.isEmpty());

		/*
		 * Sign the received XML signature digest value.
		 */
		KeyPair keyPair = generateKeyPair();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] digestInfoValue = ArrayUtils.addAll(SHA1_DIGEST_INFO_PREFIX,
				digestInfo.digestValue);
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null, new KeyUsage(KeyUsage.nonRepudiation));

		/*
		 * Operate: postSign
		 */
		testedInstance.postSign(signatureValue, Collections
				.singletonList(certificate));

		byte[] signedDocumentData = testedInstance.getSignedDocumentData();
		assertNotNull(signedDocumentData);
		Document signedDocument = loadDocument(new ByteArrayInputStream(
				signedDocumentData));
		LOG.debug("signed document: " + toString(signedDocument));

		NodeList signatureNodeList = signedDocument.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Node signatureNode = signatureNodeList.item(0);

		DOMValidateContext domValidateContext = new DOMValidateContext(
				KeySelector.singletonKeySelector(keyPair.getPublic()),
				signatureNode);
		URIDereferencer dereferencer = new URITestDereferencer();
		domValidateContext.setURIDereferencer(dereferencer);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		XMLSignature xmlSignature = xmlSignatureFactory
				.unmarshalXMLSignature(domValidateContext);
		boolean validity = xmlSignature.validate(domValidateContext);
		assertTrue(validity);
	}

	private static class URITestDereferencer implements URIDereferencer {

		private static final Log LOG = LogFactory
				.getLog(URITestDereferencer.class);

		public Data dereference(URIReference uriReference,
				XMLCryptoContext context) throws URIReferenceException {
			LOG.debug("dereference: " + uriReference.getURI());
			return new OctetStreamData(new ByteArrayInputStream("hello world"
					.getBytes()));
		}
	}

	@Test
	public void testJsr105Signature() throws Exception {
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, null, new KeyUsage(KeyUsage.nonRepudiation));

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();
		Element rootElement = document.createElementNS("urn:test", "tns:root");
		rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
				"urn:test");
		document.appendChild(rootElement);
		Element dataElement = document.createElementNS("urn:test", "tns:data");
		dataElement.setAttributeNS(null, "Id", "id-1234");
		dataElement.setTextContent("data to be signed");
		rootElement.appendChild(dataElement);

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());

		XMLSignContext signContext = new DOMSignContext(keyPair.getPrivate(),
				document.getDocumentElement());
		signContext.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory.newReference("#id-1234",
				digestMethod);
		DOMReference domReference = (DOMReference) reference;
		assertNull(domReference.getCalculatedDigestValue());
		assertNull(domReference.getDigestValue());

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null);
		SignedInfo signedInfo = signatureFactory.newSignedInfo(
				canonicalizationMethod, signatureMethod, Collections
						.singletonList(reference));

		javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
				.newXMLSignature(signedInfo, null);

		DOMXMLSignature domXmlSignature = (DOMXMLSignature) xmlSignature;
		domXmlSignature.marshal(document.getDocumentElement(), "ds",
				(DOMCryptoContext) signContext);
		domReference.digest(signContext);
		// xmlSignature.sign(signContext);
		// LOG.debug("signed document: " + toString(document));

		Element nsElement = document.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		Node digestValueNode = XPathAPI.selectSingleNode(document,
				"//ds:DigestValue", nsElement);
		assertNotNull(digestValueNode);
		String digestValueTextContent = digestValueNode.getTextContent();
		LOG.debug("digest value text content: " + digestValueTextContent);
		assertFalse(digestValueTextContent.isEmpty());
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

	private String toString(Node dom) throws TransformerException {
		Source source = new DOMSource(dom);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		/*
		 * We have to omit the ?xml declaration if we want to embed the
		 * document.
		 */
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(publicKey
				.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}

	private X509Certificate generateCertificate(PublicKey subjectPublicKey,
			String subjectDn, DateTime notBefore, DateTime notAfter,
			X509Certificate issuerCertificate, PrivateKey issuerPrivateKey,
			boolean caFlag, int pathLength, String crlUri, String ocspUri,
			KeyUsage keyUsage) throws IOException, InvalidKeyException,
			IllegalStateException, NoSuchAlgorithmException,
			SignatureException, CertificateException {
		String signatureAlgorithm = "SHA1withRSA";
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		X509Principal issuerDN;
		if (null != issuerCertificate) {
			issuerDN = new X509Principal(issuerCertificate
					.getSubjectX500Principal().toString());
		} else {
			issuerDN = new X509Principal(subjectDn);
		}
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));
		PublicKey issuerPublicKey;
		issuerPublicKey = subjectPublicKey;
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		if (caFlag) {
			if (-1 == pathLength) {
				certificateGenerator.addExtension(
						X509Extensions.BasicConstraints, false,
						new BasicConstraints(true));
			} else {
				certificateGenerator.addExtension(
						X509Extensions.BasicConstraints, false,
						new BasicConstraints(pathLength));
			}
		}

		if (null != crlUri) {
			GeneralName gn = new GeneralName(
					GeneralName.uniformResourceIdentifier, new DERIA5String(
							crlUri));
			GeneralNames gns = new GeneralNames(new DERSequence(gn));
			DistributionPointName dpn = new DistributionPointName(0, gns);
			DistributionPoint distp = new DistributionPoint(dpn, null, null);
			certificateGenerator.addExtension(
					X509Extensions.CRLDistributionPoints, false,
					new DERSequence(distp));
		}

		if (null != ocspUri) {
			GeneralName ocspName = new GeneralName(
					GeneralName.uniformResourceIdentifier, ocspUri);
			AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
					X509ObjectIdentifiers.ocspAccessMethod, ocspName);
			certificateGenerator.addExtension(
					X509Extensions.AuthorityInfoAccess.getId(), false,
					authorityInformationAccess);
		}

		if (null != keyUsage) {
			certificateGenerator.addExtension(X509Extensions.KeyUsage, true,
					keyUsage);
		}

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}
}
