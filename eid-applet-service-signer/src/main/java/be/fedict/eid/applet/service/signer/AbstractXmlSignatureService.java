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

package be.fedict.eid.applet.service.signer;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
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
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.jcp.xml.dsig.internal.dom.DOMReference;
import org.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.jcp.xml.dsig.internal.dom.DOMXMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.spi.DigestInfo;
import be.fedict.eid.applet.service.spi.SignatureService;

/**
 * Abstract base class for an XML Signature Service implementation.
 * 
 * @author fcorneli
 * 
 */
public abstract class AbstractXmlSignatureService implements SignatureService {

	private static final Log LOG = LogFactory
			.getLog(AbstractXmlSignatureService.class);

	private static final String SIGNATURE_ID_ATTRIBUTE = "signature-id";

	/**
	 * Gives back the signature digest algorithm. Allowed values are SHA-1,
	 * SHA-256, SHA-384, SHA-512, RIPEND160. The default algorithm is SHA-1.
	 * Override this method to select another signature digest algorithm.
	 * 
	 * @return
	 */
	protected String getSignatureDigestAlgorithm() {
		return "SHA-1";
	}

	/**
	 * Gives back a list of service digest infos. Override this method to
	 * provide digest infos of files located in the service itself.
	 * 
	 * @return
	 */
	protected List<DigestInfo> getServiceDigestInfos() {
		return new LinkedList<DigestInfo>();
	}

	/**
	 * Gives back the enveloping document. Return <code>null</code> in case
	 * ds:Signature should be the top-level element. Implementations can
	 * override this method to provide a custom enveloping document.
	 * 
	 * @return
	 * @throws SAXException
	 * @throws IOException
	 */
	protected Document getEnvelopingDocument()
			throws ParserConfigurationException, IOException, SAXException {
		return null;
	}

	/**
	 * Gives back a list of reference URIs that need to be signed. These URIs
	 * can refer to elements inside the enveloping document or to external
	 * resources. Override this method to feed in other ds:Reference URIs.
	 * 
	 * @return
	 */
	protected List<String> getReferenceUris() {
		return new LinkedList<String>();
	}

	public static class ReferenceInfo {
		private final String uri;
		private final String transform;

		public ReferenceInfo(String uri, String transform) {
			this.uri = uri;
			this.transform = transform;
		}

		public ReferenceInfo(String uri) {
			this(uri, null);
		}

		public String getUri() {
			return this.uri;
		}

		public String getTransform() {
			return this.transform;
		}
	}

	/**
	 * Gives back a list of references that need to be signed. Implementation
	 * can override this method.
	 * 
	 * @return
	 */
	protected List<ReferenceInfo> getReferences() {
		return new LinkedList<ReferenceInfo>();
	}

	/**
	 * Override this method to change the URI dereferener used by the signing
	 * engine.
	 * 
	 * @return
	 */
	protected URIDereferencer getURIDereferencer() {
		return null;
	}

	/**
	 * Gives back the human-readable description of what the citizen will be
	 * signing. The default value is "XML Signature". Override this method to
	 * provide the citizen with another description.
	 * 
	 * @return
	 */
	protected String getSignatureDescription() {
		return "XML Signature";
	}

	/**
	 * Gives back a temporary data storage component. This component is used for
	 * temporary storage of the XML signature documents.
	 * 
	 * @return
	 */
	protected abstract TemporaryDataStorage getTemporaryDataStorage();

	/**
	 * Gives back the output stream to which to write the signed XML document.
	 * 
	 * @return
	 */
	protected abstract OutputStream getSignedDocumentOutputStream();

	public DigestInfo preSign(List<DigestInfo> digestInfos,
			List<X509Certificate> signingCertificateChain)
			throws NoSuchAlgorithmException {
		LOG.debug("preSign");
		String digestAlgo = getSignatureDigestAlgorithm();

		byte[] digestValue;
		try {
			digestValue = getXmlSignatureDigestValue(digestAlgo, digestInfos);
		} catch (Exception e) {
			throw new RuntimeException(
					"XML signature error: " + e.getMessage(), e);
		}

		String description = getSignatureDescription();
		return new DigestInfo(digestValue, digestAlgo, description);
	}

	/**
	 * Can be overridden by XML signature service implementation to further
	 * process the signed XML document.
	 * 
	 * @param sinatureElement
	 * @param signingCertificateChain
	 */
	protected void postSign(Element sinatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}

	public void postSign(byte[] signatureValue,
			List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");

		/*
		 * Retrieve the intermediate XML signature document from the temporary
		 * data storage.
		 */
		TemporaryDataStorage temporaryDataStorage = getTemporaryDataStorage();
		InputStream documentInputStream = temporaryDataStorage
				.getTempInputStream();
		String signatureId = (String) temporaryDataStorage
				.getAttribute(SIGNATURE_ID_ATTRIBUTE);
		LOG.debug("signature Id: " + signatureId);

		/*
		 * Load the signature DOM document.
		 */
		Document document;
		try {
			document = loadDocument(documentInputStream);
		} catch (Exception e) {
			throw new RuntimeException("DOM error: " + e.getMessage(), e);
		}

		/*
		 * Locate the correct ds:Signature node.
		 */
		Element nsElement = document.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		Element signatureElement;
		try {
			signatureElement = (Element) XPathAPI.selectSingleNode(document,
					"//ds:Signature[@Id='" + signatureId + "']", nsElement);
		} catch (TransformerException e) {
			throw new RuntimeException("XPATH error: " + e.getMessage(), e);
		}
		if (null == signatureElement) {
			throw new RuntimeException("ds:Signature not found for @Id: "
					+ signatureId);
		}

		/*
		 * Insert signature value into the ds:SignatureValue element
		 */
		NodeList signatureValueNodeList = signatureElement
				.getElementsByTagNameNS(
						javax.xml.crypto.dsig.XMLSignature.XMLNS,
						"SignatureValue");
		Element signatureValueElement = (Element) signatureValueNodeList
				.item(0);
		signatureValueElement.setTextContent(Base64.encode(signatureValue));

		/*
		 * Allow implementation classes to inject their own stuff.
		 */
		postSign(signatureElement, signingCertificateChain);

		OutputStream signedDocumentOutputStream = getSignedDocumentOutputStream();
		if (null == signedDocumentOutputStream) {
			throw new IllegalArgumentException(
					"signed document output stream is null");
		}
		try {
			writeDocument(document, signedDocumentOutputStream);
		} catch (Exception e) {
			LOG.debug("error writing the signed XML document: "
					+ e.getMessage(), e);
			throw new RuntimeException(
					"error writing the signed XML document: " + e.getMessage(),
					e);
		}
	}

	private byte[] getXmlSignatureDigestValue(String digestAlgo,
			List<DigestInfo> digestInfos) throws ParserConfigurationException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			MarshalException, javax.xml.crypto.dsig.XMLSignatureException,
			TransformerFactoryConfigurationError, TransformerException,
			IOException, SAXException {
		/*
		 * DOM Document construction.
		 */
		Document document = getEnvelopingDocument();
		if (null == document) {
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
					.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder documentBuilder = documentBuilderFactory
					.newDocumentBuilder();
			document = documentBuilder.newDocument();
		}

		/*
		 * Signature context construction.
		 */
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
		XMLSignContext xmlSignContext = new DOMSignContext(key, document);
		URIDereferencer uriDereferencer = getURIDereferencer();
		if (null != uriDereferencer) {
			xmlSignContext.setURIDereferencer(uriDereferencer);
		}

		// OOo doesn't like ds namespaces.
		// xmlSignContext.putNamespacePrefix(
		// javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");

		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance(
				"DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());

		/*
		 * ds:Reference
		 */
		List<Reference> references = new LinkedList<Reference>();
		addDigestInfosAsReferences(digestInfos, signatureFactory, references);
		List<DigestInfo> serviceDigestInfos = getServiceDigestInfos();
		addDigestInfosAsReferences(serviceDigestInfos, signatureFactory,
				references);
		addReferenceIds(signatureFactory, xmlSignContext, references);
		addReferences(signatureFactory, references);

		/*
		 * ds:SignedInfo
		 */
		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				getSignatureMethod(digestAlgo), null);
		// CanonicalizationMethod.INCLUSIVE fails for OOo
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
						(C14NMethodParameterSpec) null);
		SignedInfo signedInfo = signatureFactory.newSignedInfo(
				canonicalizationMethod, signatureMethod, references);

		/*
		 * ds:Signature marshalling
		 */
		String signatureId = "xmldsig-" + UUID.randomUUID().toString();
		javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
				.newXMLSignature(signedInfo, null, null, signatureId, null);
		DOMXMLSignature domXmlSignature = (DOMXMLSignature) xmlSignature;
		Node documentNode = document.getDocumentElement();
		if (null == documentNode) {
			/*
			 * In case of an empty DOM document.
			 */
			documentNode = document;
		}
		String dsPrefix = null;
		// String dsPrefix = "ds";
		domXmlSignature.marshal(documentNode, dsPrefix,
				(DOMCryptoContext) xmlSignContext);

		/*
		 * Completion of undigested ds:References.
		 */
		List<Reference> signedInfoReferences = signedInfo.getReferences();
		for (Reference signedInfoReference : signedInfoReferences) {
			DOMReference domReference = (DOMReference) signedInfoReference;
			if (null != domReference.getDigestValue()) {
				// ds:Reference with external digest value
				continue;
			}
			domReference.digest(xmlSignContext);
		}

		/*
		 * Store the intermediate XML signature document.
		 */
		TemporaryDataStorage temporaryDataStorage = getTemporaryDataStorage();
		OutputStream tempDocumentOutputStream = temporaryDataStorage
				.getTempOutputStream();
		writeDocument(document, tempDocumentOutputStream);
		temporaryDataStorage.setAttribute(SIGNATURE_ID_ATTRIBUTE, signatureId);

		/*
		 * Calculation of XML signature digest value.
		 */
		DOMSignedInfo domSignedInfo = (DOMSignedInfo) signedInfo;
		ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
		domSignedInfo.canonicalize(xmlSignContext, dataStream);
		byte[] octets = dataStream.toByteArray();

		/*
		 * TODO: we could be using DigestOutputStream here to optimize memory
		 * usage.
		 */

		MessageDigest jcaMessageDigest = MessageDigest.getInstance(digestAlgo);
		byte[] digestValue = jcaMessageDigest.digest(octets);
		return digestValue;
	}

	private void addReferenceIds(XMLSignatureFactory signatureFactory,
			XMLSignContext xmlSignContext, List<Reference> references)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, XMLSignatureException {
		List<String> referenceUris = getReferenceUris();
		if (null == referenceUris) {
			return;
		}
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		for (String referenceUri : referenceUris) {
			Reference reference = signatureFactory.newReference(referenceUri,
					digestMethod);
			references.add(reference);
		}
	}

	private void addReferences(XMLSignatureFactory xmlSignatureFactory,
			List<Reference> references) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		List<ReferenceInfo> referenceInfos = getReferences();
		if (null == referenceInfos) {
			return;
		}
		if (referenceInfos.isEmpty()) {
			return;
		}
		DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		for (ReferenceInfo referenceInfo : referenceInfos) {
			List<Transform> transforms = new LinkedList<Transform>();
			if (null != referenceInfo.getTransform()) {
				Transform transform = xmlSignatureFactory.newTransform(
						referenceInfo.getTransform(),
						(TransformParameterSpec) null);
				transforms.add(transform);
			}
			Reference reference = xmlSignatureFactory.newReference(
					referenceInfo.getUri(), digestMethod, transforms, null,
					null);
			references.add(reference);
		}
	}

	private void addDigestInfosAsReferences(List<DigestInfo> digestInfos,
			XMLSignatureFactory signatureFactory, List<Reference> references)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MalformedURLException {
		if (null == digestInfos) {
			return;
		}
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
			return XMLSignature.ALGO_ID_MAC_HMAC_SHA512;
		}
		if ("SHA-384".equals(digestAlgo)) {
			return XMLSignature.ALGO_ID_MAC_HMAC_SHA384;
		}
		if ("RIPEMD160".equals(digestAlgo)) {
			return XMLSignature.ALGO_ID_MAC_HMAC_RIPEMD160;
		}
		throw new RuntimeException("unsupported sign algo: " + digestAlgo);
	}

	private void writeDocument(Document document,
			OutputStream documentOutputStream)
			throws TransformerConfigurationException,
			TransformerFactoryConfigurationError, TransformerException,
			IOException {
		Result result = new StreamResult(documentOutputStream);
		Transformer xformer = TransformerFactory.newInstance().newTransformer();
		xformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		Source source = new DOMSource(document);
		xformer.transform(source, result);
		documentOutputStream.close();
	}

	protected Document loadDocument(InputStream documentInputStream)
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
