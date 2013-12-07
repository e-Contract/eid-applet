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

package test.unit.test.be.fedict.eid.applet.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignature;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xpath.XPathAPI;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import test.be.fedict.eid.applet.model.XmlSignatureServiceBean;
import be.fedict.eid.applet.service.spi.DigestInfo;

public class XmlSignatureServiceBeanTest {

	public class ResourceTestResolver extends ResourceResolverSpi {

		private final Log LOG = LogFactory.getLog(ResourceTestResolver.class);

		private final Map<String, byte[]> resources;

		public ResourceTestResolver() {
			this.resources = new HashMap<String, byte[]>();
		}

		public void addResource(String uri, byte[] value) {
			this.resources.put(uri, value);
		}

		@Override
		public boolean engineCanResolve(Attr uri, String baseURI) {
			LOG.debug("engine can resolve: " + uri.getValue());
			return this.resources.containsKey(uri.getValue());
		}

		@Override
		public XMLSignatureInput engineResolve(Attr uri, String baseURI)
				throws ResourceResolverException {
			LOG.debug("engine resolve: " + uri.getValue());
			if (false == this.resources.containsKey(uri.getValue())) {
				return null;
			}
			return new XMLSignatureInput(this.resources.get(uri.getValue()));
		}
	}

	private static final Log LOG = LogFactory
			.getLog(XmlSignatureServiceBeanTest.class);

	private XmlSignatureServiceBean testedInstance;

	@Before
	public void setUp() throws Exception {
		Init.init();
		this.testedInstance = new XmlSignatureServiceBean();
	}

	public static final byte[] SHA1_DIGEST_INFO_PREFIX = new byte[] { 0x30,
			0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04,
			0x14 };

	@Test
	public void testFilenamesForUri() throws Exception {
		LOG.debug("test.txt: " + new URI("test.txt"));
		LOG.debug("1234.txt: " + new URI("1234.txt"));
		LOG.debug("hello world.txt: "
				+ new File("hello world.txt").toURI().toURL().getFile());
		LOG.debug("hello world.txt: "
				+ FilenameUtils.getName(new File("hello world.txt").toURI()
						.toURL().getFile()));
	}

	@Test
	public void testExternalXmlSignature() throws Exception {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();

		XMLSignature xmlSignature = new XMLSignature(document, "",
				XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
				Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);

		Element signatureElement = xmlSignature.getElement();
		document.appendChild(signatureElement);

		ObjectContainer objectContainer = new ObjectContainer(document);
		objectContainer.appendChild(document.createTextNode("Test Message"));
		String id = "object-" + UUID.randomUUID().toString();
		objectContainer.setId(id);
		xmlSignature.appendObject(objectContainer);

		Transforms transforms = new Transforms(document);
		transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS);
		xmlSignature.addDocument("#" + id, transforms,
				MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, null, null);

		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, new KeyUsage(KeyUsage.nonRepudiation));

		xmlSignature.addKeyInfo(certificate);

		SignedInfo signedInfo = xmlSignature.getSignedInfo();
		signedInfo.generateDigestValues();
		byte[] octets = signedInfo.getCanonicalizedOctetStream();

		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] digestValue = messageDigest.digest(octets);
		byte[] digestInfoValue = ArrayUtils.addAll(SHA1_DIGEST_INFO_PREFIX,
				digestValue);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		String encodedSignatureValue = Base64.encode(signatureValue);
		Element xmlSignatureElement = xmlSignature.getElement();
		Element signatureValueElement = (Element) XPathAPI.selectSingleNode(
				xmlSignatureElement, "ds:SignatureValue");
		signatureValueElement.setTextContent(encodedSignatureValue);

		xmlSignature = new XMLSignature(xmlSignatureElement, null);
		assertTrue(xmlSignature.checkSignatureValue(keyPair.getPublic()));

		Source source = new DOMSource(document);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		Transformer xformer = TransformerFactory.newInstance().newTransformer();
		xformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xformer.transform(source, result);
		String signedDocumentStr = stringWriter.getBuffer().toString();
		LOG.debug("signed document: " + signedDocumentStr);

		File tmpFile = File.createTempFile("signature-", ".xml");
		IOUtils.write(signedDocumentStr.getBytes(), new FileOutputStream(
				tmpFile));

		StringReader stringReader = new StringReader(signedDocumentStr);
		InputSource inputSource = new InputSource(stringReader);
		Document signedDocument = documentBuilder.parse(inputSource);

		signatureElement = (Element) XPathAPI.selectSingleNode(signedDocument,
				"ds:Signature");
		assertNotNull(signatureElement);

		xmlSignature = new XMLSignature(signatureElement, null);
		LOG.debug("tmp signature file: " + tmpFile.getAbsolutePath());
		boolean signatureResult = xmlSignature.checkSignatureValue(keyPair
				.getPublic());
		assertTrue(signatureResult);
	}

	@Test
	public void testJsr105ReferenceUri() throws Exception {
		String uri = FilenameUtils.getName(new File("foo bar.txt").toURI()
				.toURL().getFile());

		KeyPair keyPair = generateKeyPair();

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new XMLDSigRI());

		XMLSignContext signContext = new DOMSignContext(keyPair.getPrivate(),
				document);

		byte[] externalDocument = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		messageDigest.update(externalDocument);
		byte[] documentDigestValue = messageDigest.digest();

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory.newReference(uri, digestMethod,
				null, null, null, documentDigestValue);

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null);
		javax.xml.crypto.dsig.SignedInfo signedInfo = signatureFactory
				.newSignedInfo(canonicalizationMethod, signatureMethod,
						Collections.singletonList(reference));

		javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
				.newXMLSignature(signedInfo, null);

		xmlSignature.sign(signContext);
	}

	@Test
	public void testJsr105Signature() throws Exception {
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, new KeyUsage(KeyUsage.nonRepudiation));

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new XMLDSigRI());

		XMLSignContext signContext = new DOMSignContext(keyPair.getPrivate(),
				document);
		signContext.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		byte[] externalDocument = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		messageDigest.update(externalDocument);
		byte[] documentDigestValue = messageDigest.digest();

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory.newReference("some-uri",
				digestMethod, null, null, null, documentDigestValue);

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null);
		javax.xml.crypto.dsig.SignedInfo signedInfo = signatureFactory
				.newSignedInfo(canonicalizationMethod, signatureMethod,
						Collections.singletonList(reference));

		KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
		X509Data x509Data = keyInfoFactory.newX509Data(Collections
				.singletonList(certificate));
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections
				.singletonList(x509Data));

		javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
				.newXMLSignature(signedInfo, keyInfo);
		DOMXMLSignature domXmlSignature = (DOMXMLSignature) xmlSignature;
		domXmlSignature.marshal(document, "ds", (DOMCryptoContext) signContext);

		DOMSignedInfo domSignedInfo = (DOMSignedInfo) signedInfo;
		ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
		domSignedInfo.canonicalize(signContext, dataStream);
		byte[] octets = dataStream.toByteArray();

		MessageDigest jcaMessageDigest = MessageDigest.getInstance("SHA1");
		byte[] digestValue = jcaMessageDigest.digest(octets);
		byte[] digestInfoValue = ArrayUtils.addAll(SHA1_DIGEST_INFO_PREFIX,
				digestValue);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		NodeList signatureValueNodeList = document.getElementsByTagNameNS(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "SignatureValue");
		assertEquals(1, signatureValueNodeList.getLength());
		Element signatureValueElement = (Element) signatureValueNodeList
				.item(0);
		signatureValueElement.setTextContent(Base64.encode(signatureValue));

		Source source = new DOMSource(document);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		Transformer xformer = TransformerFactory.newInstance().newTransformer();
		xformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xformer.transform(source, result);
		String signedDocumentStr = stringWriter.getBuffer().toString();
		LOG.debug("signed document: " + signedDocumentStr);

		File tmpFile = File.createTempFile("xml-signature-", ".xml");
		FileUtils.writeStringToFile(tmpFile, signedDocumentStr);

		StringReader stringReader = new StringReader(signedDocumentStr);
		InputSource inputSource = new InputSource(stringReader);
		Document signedDocument = documentBuilder.parse(inputSource);

		Element signatureElement = (Element) XPathAPI.selectSingleNode(
				signedDocument, "ds:Signature");
		assertNotNull(signatureElement);

		XMLSignature apacheXmlSignature = new XMLSignature(signatureElement,
				null);
		ResourceTestResolver resourceResolver = new ResourceTestResolver();
		resourceResolver.addResource("some-uri", "hello world".getBytes());
		apacheXmlSignature.addResourceResolver(resourceResolver);
		boolean signatureResult = apacheXmlSignature
				.checkSignatureValue(keyPair.getPublic());
		assertTrue(signatureResult);

		LOG.debug("file: " + tmpFile.getAbsolutePath());
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
		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}

	private X509Certificate generateCertificate(PublicKey subjectPublicKey,
			String subjectDn, DateTime notBefore, DateTime notAfter,
			X509Certificate issuerCertificate, PrivateKey issuerPrivateKey,
			boolean caFlag, int pathLength, String ocspUri, KeyUsage keyUsage)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
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

	@Test
	public void testPreSignPostSign() throws Exception {
		// setup
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusYears(1);
		X509Certificate certificate = generateCertificate(keyPair.getPublic(),
				"CN=Test", notBefore, notAfter, null, keyPair.getPrivate(),
				true, 0, null, new KeyUsage(KeyUsage.nonRepudiation));

		byte[] toBeSigned = "hello world".getBytes();
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] digestValue = messageDigest.digest(toBeSigned);

		List<DigestInfo> digestInfos = new LinkedList<DigestInfo>();
		digestInfos.add(new DigestInfo(digestValue, "SHA-1", "test-file-name"));

		HttpServletRequest mockHttpServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		EasyMock.expect(mockHttpServletRequest.getSession()).andStubReturn(
				mockHttpSession);
		// XML signature digest algorithm
		EasyMock.expect(mockHttpSession.getAttribute("signDigestAlgo"))
				.andStubReturn("SHA-1");

		PolicyContextHandler handler = new PolicyContextTestHandler(
				mockHttpServletRequest);
		PolicyContext.registerHandler("javax.servlet.http.HttpServletRequest",
				handler, false);

		Capture<String> xmlDocumentCapture = new Capture<String>();
		mockHttpSession.setAttribute(EasyMock.eq("xmlDocument"),
				EasyMock.capture(xmlDocumentCapture));

		// prepare
		EasyMock.replay(mockHttpServletRequest, mockHttpSession);

		// operate
		DigestInfo resultDigestInfo = this.testedInstance.preSign(digestInfos,
				null);

		// verify
		EasyMock.verify(mockHttpServletRequest, mockHttpSession);
		assertNotNull(resultDigestInfo);
		assertNotNull(resultDigestInfo.digestValue);
		assertNotNull(resultDigestInfo.digestAlgo);
		assertNotNull(resultDigestInfo.description);
		LOG.debug("digest algo: " + resultDigestInfo.digestAlgo);
		LOG.debug("description: " + resultDigestInfo.description);

		// create the external signature
		byte[] digestInfoValue = ArrayUtils.addAll(SHA1_DIGEST_INFO_PREFIX,
				resultDigestInfo.digestValue);

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte[] signatureValue = cipher.doFinal(digestInfoValue);

		List<X509Certificate> signingCertificateChain = new LinkedList<X509Certificate>();
		signingCertificateChain.add(certificate);

		// setup
		EasyMock.reset(mockHttpServletRequest, mockHttpSession);

		EasyMock.expect(mockHttpServletRequest.getSession()).andStubReturn(
				mockHttpSession);
		EasyMock.expect(mockHttpSession.getAttribute("xmlDocument")).andReturn(
				xmlDocumentCapture.getValue());
		mockHttpSession.setAttribute(EasyMock.eq("xmlDocument"),
				EasyMock.capture(xmlDocumentCapture));

		// prepare
		EasyMock.replay(mockHttpServletRequest, mockHttpSession);

		// operate
		this.testedInstance.postSign(signatureValue, signingCertificateChain);

		// verify
		EasyMock.verify(mockHttpServletRequest, mockHttpSession);

		String signedDocumentStr = xmlDocumentCapture.getValue();
		StringReader stringReader = new StringReader(signedDocumentStr);
		InputSource inputSource = new InputSource(stringReader);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document signedDocument = documentBuilder.parse(inputSource);

		Element signatureElement = (Element) XPathAPI.selectSingleNode(
				signedDocument, "ds:Signature");
		assertNotNull(signatureElement);

		XMLSignature apacheXmlSignature = new XMLSignature(signatureElement,
				null);
		ResourceTestResolver resourceResolver = new ResourceTestResolver();
		resourceResolver.addResource("test-file-name", toBeSigned);
		apacheXmlSignature.addResourceResolver(resourceResolver);
		boolean signatureResult = apacheXmlSignature
				.checkSignatureValue(keyPair.getPublic());
		assertTrue(signatureResult);

		LOG.debug("XML signature: " + xmlDocumentCapture.getValue());
	}

	private static class PolicyContextTestHandler implements
			PolicyContextHandler {

		private final HttpServletRequest httpServletRequest;

		public PolicyContextTestHandler(HttpServletRequest httpServletRequest) {
			this.httpServletRequest = httpServletRequest;
		}

		public Object getContext(String key, Object data)
				throws PolicyContextException {
			if (false == "javax.servlet.http.HttpServletRequest".equals(key)) {
				return null;
			}
			return this.httpServletRequest;
		}

		public String[] getKeys() throws PolicyContextException {
			return new String[] { "javax.servlet.http.HttpServletRequest" };
		}

		public boolean supports(String key) throws PolicyContextException {
			return "javax.servlet.http.HttpServletRequest".equals(key);
		}
	}

	@Test
	public void testRegisterOwnJceProvider() throws Exception {
		MyTestProvider provider = new MyTestProvider();
		assertTrue(-1 != Security.addProvider(provider));

		MessageDigest messageDigest = MessageDigest.getInstance("SHA-1",
				MyTestProvider.NAME);
		assertEquals(MyTestProvider.NAME, messageDigest.getProvider().getName());

		messageDigest.update("hello world".getBytes());
		byte[] result = messageDigest.digest();

		Assert.assertArrayEquals("hello world".getBytes(), result);

		Security.removeProvider(MyTestProvider.NAME);
	}

	private static class MyTestProvider extends Provider {

		private static final long serialVersionUID = 1L;

		public static final String NAME = MyTestProvider.class.getSimpleName();

		protected MyTestProvider() {
			super(NAME, 1.0, "Test JCE Provider");
			put("MessageDigest.SHA-1", MyTestMessageDigest.class.getName());
		}
	}

	/**
	 * This is a non-digesting message digest implementation. We assume we
	 * already receive a digested value.
	 * 
	 * @author Frank Cornelis
	 * 
	 */
	public static class MyTestMessageDigest extends MessageDigest {

		private final ByteArrayOutputStream byteArrayOutputStream;

		public MyTestMessageDigest() {
			super("SHA-1");
			this.byteArrayOutputStream = new ByteArrayOutputStream();
		}

		@Override
		protected byte[] engineDigest() {
			return this.byteArrayOutputStream.toByteArray();
		}

		@Override
		protected void engineReset() {
			this.byteArrayOutputStream.reset();
		}

		@Override
		protected void engineUpdate(byte input) {
			this.byteArrayOutputStream.write(input);
		}

		@Override
		protected void engineUpdate(byte[] input, int offset, int len) {
			this.byteArrayOutputStream.write(input, offset, len);
		}
	}
}
