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

package test.be.fedict.eid.applet.model;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignature;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Base64;
import org.jboss.ejb3.annotation.LocalBinding;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.SignatureService;

@Stateless
@Local(SignatureService.class)
@LocalBinding(jndiBinding = "test/eid/applet/model/XmlSignatureServiceBean")
public class XmlSignatureServiceBean implements SignatureService {

	private static final Log LOG = LogFactory
			.getLog(XmlSignatureServiceBean.class);

	public void postSign(byte[] signatureValue,
			List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");

		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession session = httpServletRequest.getSession();
		String documentStr = (String) session.getAttribute("xmlDocument");

		Document document;
		try {
			document = getDocument(documentStr);
		} catch (Exception e) {
			throw new RuntimeException("DOM error: " + e.getMessage(), e);
		}

		// insert signature value
		NodeList signatureValueNodeList = document.getElementsByTagNameNS(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "SignatureValue");
		Element signatureValueElement = (Element) signatureValueNodeList
				.item(0);
		signatureValueElement.setTextContent(Base64.encode(signatureValue));

		try {
			documentStr = toString(document);
		} catch (Exception e) {
			throw new RuntimeException("DOM error: " + e.getMessage(), e);
		}

		session.setAttribute("xmlDocument", documentStr);
	}

	private String toString(Document document)
			throws TransformerConfigurationException,
			TransformerFactoryConfigurationError, TransformerException {
		String documentStr;
		Source source = new DOMSource(document);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		Transformer xformer = TransformerFactory.newInstance().newTransformer();
		xformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xformer.transform(source, result);
		documentStr = stringWriter.getBuffer().toString();
		return documentStr;
	}

	private Document getDocument(String documentStr)
			throws ParserConfigurationException, SAXException, IOException {
		StringReader stringReader = new StringReader(documentStr);
		InputSource inputSource = new InputSource(stringReader);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(inputSource);
		return document;
	}

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain)
			throws NoSuchAlgorithmException {
		LOG.debug("preSign");
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession httpSession = httpServletRequest.getSession();
		String digestAlgo = (String) httpSession.getAttribute("signDigestAlgo");
		LOG.debug("digest algo: " + digestAlgo);

		byte[] digestValue;
		try {
			digestValue = getXmlSignatureDigestValue(digestAlgo, digestInfos,
					httpSession);
		} catch (Exception e) {
			throw new RuntimeException(
					"XML signature error: " + e.getMessage(), e);
		}

		String description = "Test XML Document";
		return new DigestInfo(digestValue, digestAlgo, description);
	}

	private byte[] getXmlSignatureDigestValue(String digestAlgo,
			List<DigestInfo> digestInfos, HttpSession httpSession)
			throws ParserConfigurationException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException,
			javax.xml.crypto.dsig.XMLSignatureException,
			TransformerFactoryConfigurationError, TransformerException,
			MalformedURLException {

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.newDocument();

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new XMLDSigRI());

		Key key = new Key() {
			private static final long serialVersionUID = 1L;

			public String getAlgorithm() {
				return null;
			}

			public byte[] getEncoded() {
				return null;
			}

			public String getFormat() {
				return null;
			}
		};
		XMLSignContext signContext = new DOMSignContext(key, document);
		signContext.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		List<Reference> references = new LinkedList<Reference>();
		for (DigestInfo digestInfo : digestInfos) {
			byte[] documentDigestValue = digestInfo.digestValue;

			DigestMethod digestMethod = signatureFactory.newDigestMethod(
					getXmlDigestAlgo(digestInfo.digestAlgo), null);

			String uri = FilenameUtils.getName(new File(digestInfo.description)
					.toURI().toURL().getFile());

			Reference reference = signatureFactory.newReference(uri,
					digestMethod, null, null, null, documentDigestValue);
			references.add(reference);
		}

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				getSignatureMethod(digestAlgo), null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
						(C14NMethodParameterSpec) null);
		javax.xml.crypto.dsig.SignedInfo signedInfo = signatureFactory
				.newSignedInfo(canonicalizationMethod, signatureMethod,
						references);

		javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
				.newXMLSignature(signedInfo, null);
		DOMXMLSignature domXmlSignature = (DOMXMLSignature) xmlSignature;
		domXmlSignature.marshal(document, "ds", (DOMCryptoContext) signContext);

		Source source = new DOMSource(document);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		Transformer xformer = TransformerFactory.newInstance().newTransformer();
		xformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		xformer.transform(source, result);
		String documentStr = stringWriter.getBuffer().toString();
		httpSession.setAttribute("xmlDocument", documentStr);

		DOMSignedInfo domSignedInfo = (DOMSignedInfo) signedInfo;
		ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
		domSignedInfo.canonicalize(signContext, dataStream);
		byte[] octets = dataStream.toByteArray();

		MessageDigest jcaMessageDigest = MessageDigest.getInstance(digestAlgo);
		byte[] digestValue = jcaMessageDigest.digest(octets);
		return digestValue;
	}

	private String getXmlDigestAlgo(String digestAlgo) {
		if ("SHA-1".equals(digestAlgo)) {
			return DigestMethod.SHA1;
		}
		if ("SHA-256".equals(digestAlgo)) {
			return DigestMethod.SHA256;
		}
		if ("SHA-512".equals(digestAlgo)) {
			return DigestMethod.SHA512;
		}
		throw new RuntimeException("unsupported digest algo: " + digestAlgo);
	}

	private String getSignatureMethod(String digestAlgo) {
		if (null == digestAlgo) {
			throw new RuntimeException("digest algo is null");
		}
		if ("SHA-1".equals(digestAlgo)) {
			return SignatureMethod.RSA_SHA1;
		}
		if ("SHA-256".equals(digestAlgo)) {
			return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
		}
		if ("SHA-512".equals(digestAlgo)) {
			return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;
		}
		if ("SHA-384".equals(digestAlgo)) {
			return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384;
		}
		if ("RIPEMD160".equals(digestAlgo)) {
			return XMLSignature.ALGO_ID_SIGNATURE_RSA_RIPEMD160;
		}
		throw new RuntimeException("unsupported sign algo: " + digestAlgo);
	}

	public String getFilesDigestAlgorithm() {
		LOG.debug("getFileDigestAlgoritm()");
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}

		HttpSession session = httpServletRequest.getSession();
		String filesDigestAlgo = (String) session
				.getAttribute("filesDigestAlgo");
		LOG.debug("files digest algo: " + filesDigestAlgo);

		return filesDigestAlgo;
	}
}
