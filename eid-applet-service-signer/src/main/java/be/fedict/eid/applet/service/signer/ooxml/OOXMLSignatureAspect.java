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

package be.fedict.eid.applet.service.signer.ooxml;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.SignatureAspect;

/**
 * Office OpenXML Signature Aspect implementation.
 * 
 * @author fcorneli
 * 
 */
public class OOXMLSignatureAspect implements SignatureAspect {

	private static final Log LOG = LogFactory
			.getLog(OOXMLSignatureAspect.class);

	private final AbstractOOXMLSignatureService signatureService;

	/**
	 * Main constructor.
	 * 
	 * @param ooxmlUrl
	 */
	public OOXMLSignatureAspect(AbstractOOXMLSignatureService signatureService) {
		this.signatureService = signatureService;
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, List<Reference> references,
			List<XMLObject> objects) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		LOG.debug("pre sign");
		List<Reference> manifestReferences = new LinkedList<Reference>();
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
				manifestReferences);
		addParts(signatureFactory,
				"application/vnd.openxmlformats-officedocument.theme+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml",
				manifestReferences);

		try {
			addRelationshipsReferences(signatureFactory, document,
					manifestReferences);
		} catch (Exception e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}

		Manifest manifest = signatureFactory.newManifest(manifestReferences);
		String objectId = "ooxml-manifest-object-"
				+ UUID.randomUUID().toString();
		objects.add(signatureFactory.newXMLObject(Collections
				.singletonList(manifest), objectId, null, null));

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory.newReference("#" + objectId,
				digestMethod);
		references.add(reference);
	}

	private void addRelationshipsReferences(
			XMLSignatureFactory signatureFactory, Document document,
			List<Reference> manifestReferences) throws IOException,
			ParserConfigurationException, SAXException, TransformerException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		Document _relsDotRels = loadDocument("_rels/.rels");
		Element nsElement = _relsDotRels.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
				"http://schemas.openxmlformats.org/package/2006/relationships");
		Node idNode = XPathAPI
				.selectSingleNode(
						_relsDotRels,
						"/tns:Relationships/tns:Relationship[@Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument']/@Id",
						nsElement);
		String relId = idNode.getTextContent();
		LOG.debug("Office document relationship Id: " + relId);
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		List<Transform> transforms = new LinkedList<Transform>();
		Element transformContentElement = document
				.createElementNS(
						"http://schemas.openxmlformats.org/package/2006/digital-signature",
						"mdssi:RelationshipReference");
		transformContentElement
				.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:mdssi",
						"http://schemas.openxmlformats.org/package/2006/digital-signature");
		transformContentElement.setAttribute("SourceId", relId);
		transforms
				.add(signatureFactory
						.newTransform(
								"http://schemas.openxmlformats.org/package/2006/RelationshipTransform",
								new DOMStructure(transformContentElement)));
		transforms.add(signatureFactory.newTransform(
				"http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
				(TransformParameterSpec) null));
		Reference reference = signatureFactory
				.newReference(
						"/_rels/.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml",
						digestMethod, transforms, null, null);

		manifestReferences.add(reference);
		// TODO
	}

	private void addParts(XMLSignatureFactory signatureFactory,
			String contentType, List<Reference> references)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		List<String> documentResourceNames;
		try {
			documentResourceNames = getResourceNames(this.signatureService
					.getOfficeOpenXMLDocumentURL(), contentType);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		for (String documentResourceName : documentResourceNames) {
			LOG.debug("document resource: " + documentResourceName);

			Reference reference = signatureFactory.newReference("/"
					+ documentResourceName + "?ContentType=" + contentType,
					digestMethod);

			references.add(reference);
		}
	}

	private List<String> getResourceNames(URL url, String contentType)
			throws IOException, ParserConfigurationException, SAXException,
			TransformerException {
		List<String> signatureResourceNames = new LinkedList<String>();
		if (null == url) {
			throw new RuntimeException("OOXML URL is null");
		}
		InputStream inputStream = url.openStream();
		ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (false == "[Content_Types].xml".equals(zipEntry.getName())) {
				continue;
			}
			Document contentTypesDocument = loadDocument(zipInputStream);
			Element nsElement = contentTypesDocument.createElement("ns");
			nsElement
					.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
							"http://schemas.openxmlformats.org/package/2006/content-types");
			NodeList nodeList = XPathAPI.selectNodeList(contentTypesDocument,
					"/tns:Types/tns:Override[@ContentType='" + contentType
							+ "']/@PartName", nsElement);
			for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
				String partName = nodeList.item(nodeIdx).getTextContent();
				LOG.debug("part name: " + partName);
				partName = partName.substring(1); // remove '/'
				signatureResourceNames.add(partName);
			}
			break;
		}
		return signatureResourceNames;
	}

	protected Document loadDocument(String zipEntryName) throws IOException,
			ParserConfigurationException, SAXException {
		URL ooxmlUrl = this.signatureService.getOfficeOpenXMLDocumentURL();
		InputStream inputStream = ooxmlUrl.openStream();
		ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (false == zipEntryName.equals(zipEntry.getName())) {
				continue;
			}
			Document document = loadDocument(zipInputStream);
			return document;
		}
		throw new RuntimeException("ZIP entry not found: " + zipEntryName);
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
