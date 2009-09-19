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
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
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
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.NoCloseInputStream;
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
			Document document, String signatureId, List<Reference> references,
			List<XMLObject> objects) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		LOG.debug("pre sign");
		addManifestObject(signatureFactory, document, signatureId, references,
				objects);

		addSignatureInfo(signatureFactory, document, signatureId, references,
				objects);
	}

	private void addManifestObject(XMLSignatureFactory signatureFactory,
			Document document, String signatureId, List<Reference> references,
			List<XMLObject> objects) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		Manifest manifest = constructManifest(signatureFactory, document);
		String objectId = "idPackageObject"; // really has to be this value.
		List<XMLStructure> objectContent = new LinkedList<XMLStructure>();
		objectContent.add(manifest);

		addSignatureTime(signatureFactory, document, signatureId, objectContent);

		objects.add(signatureFactory.newXMLObject(objectContent, objectId,
				null, null));

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory.newReference("#" + objectId,
				digestMethod, null, "http://www.w3.org/2000/09/xmldsig#Object",
				null);
		references.add(reference);
	}

	private Manifest constructManifest(XMLSignatureFactory signatureFactory,
			Document document) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		List<Reference> manifestReferences = new LinkedList<Reference>();

		try {
			addRelationshipsReferences(signatureFactory, document,
					manifestReferences);
		} catch (Exception e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}

		/*
		 * Word
		 */
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

		/*
		 * Powerpoint
		 */
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
				manifestReferences);
		addParts(
				signatureFactory,
				"application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml",
				manifestReferences);

		Manifest manifest = signatureFactory.newManifest(manifestReferences);
		return manifest;
	}

	private void addSignatureTime(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<XMLStructure> objectContent) {
		/*
		 * SignatureTime
		 */
		Element signatureTimeElement = document
				.createElementNS(
						"http://schemas.openxmlformats.org/package/2006/digital-signature",
						"mdssi:SignatureTime");
		signatureTimeElement
				.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:mdssi",
						"http://schemas.openxmlformats.org/package/2006/digital-signature");
		Element formatElement = document
				.createElementNS(
						"http://schemas.openxmlformats.org/package/2006/digital-signature",
						"mdssi:Format");
		formatElement.setTextContent("YYYY-MM-DDThh:mm:ssTZD");
		signatureTimeElement.appendChild(formatElement);
		Element valueElement = document
				.createElementNS(
						"http://schemas.openxmlformats.org/package/2006/digital-signature",
						"mdssi:Value");
		DateTime dateTime = new DateTime(DateTimeZone.UTC);
		DateTimeFormatter fmt = ISODateTimeFormat.dateTimeNoMillis();
		String now = fmt.print(dateTime);
		LOG.debug("now: " + now);
		valueElement.setTextContent(now);
		signatureTimeElement.appendChild(valueElement);

		List<XMLStructure> signatureTimeContent = new LinkedList<XMLStructure>();
		signatureTimeContent.add(new DOMStructure(signatureTimeElement));
		SignatureProperty signatureTimeSignatureProperty = signatureFactory
				.newSignatureProperty(signatureTimeContent, "#" + signatureId,
						"idSignatureTime");
		List<SignatureProperty> signaturePropertyContent = new LinkedList<SignatureProperty>();
		signaturePropertyContent.add(signatureTimeSignatureProperty);
		SignatureProperties signatureProperties = signatureFactory
				.newSignatureProperties(signaturePropertyContent,
						"id-signature-time-" + UUID.randomUUID().toString());
		objectContent.add(signatureProperties);
	}

	private void addSignatureInfo(XMLSignatureFactory signatureFactory,
			Document document, String signatureId, List<Reference> references,
			List<XMLObject> objects) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		List<XMLStructure> objectContent = new LinkedList<XMLStructure>();

		Element signatureInfoElement = document.createElementNS(
				"http://schemas.microsoft.com/office/2006/digsig",
				"SignatureInfoV1");
		signatureInfoElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns",
				"http://schemas.microsoft.com/office/2006/digsig");

		Element manifestHashAlgorithmElement = document.createElementNS(
				"http://schemas.microsoft.com/office/2006/digsig",
				"ManifestHashAlgorithm");
		manifestHashAlgorithmElement
				.setTextContent("http://www.w3.org/2000/09/xmldsig#sha1");
		signatureInfoElement.appendChild(manifestHashAlgorithmElement);

		List<XMLStructure> signatureInfoContent = new LinkedList<XMLStructure>();
		signatureInfoContent.add(new DOMStructure(signatureInfoElement));
		SignatureProperty signatureInfoSignatureProperty = signatureFactory
				.newSignatureProperty(signatureInfoContent, "#" + signatureId,
						"idOfficeV1Details");

		List<SignatureProperty> signaturePropertyContent = new LinkedList<SignatureProperty>();
		signaturePropertyContent.add(signatureInfoSignatureProperty);
		SignatureProperties signatureProperties = signatureFactory
				.newSignatureProperties(signaturePropertyContent, null);
		objectContent.add(signatureProperties);

		String objectId = "idOfficeObject";
		objects.add(signatureFactory.newXMLObject(objectContent, objectId,
				null, null));

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory.newReference("#" + objectId,
				digestMethod, null, "http://www.w3.org/2000/09/xmldsig#Object",
				null);
		references.add(reference);
	}

	private void addRelationshipsReferences(
			XMLSignatureFactory signatureFactory, Document document,
			List<Reference> manifestReferences) throws IOException,
			ParserConfigurationException, SAXException, TransformerException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		URL ooxmlUrl = this.signatureService.getOfficeOpenXMLDocumentURL();
		InputStream inputStream = ooxmlUrl.openStream();
		ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (false == zipEntry.getName().endsWith(".rels")) {
				continue;
			}
			Document relsDocument = loadDocumentNoClose(zipInputStream);
			addRelationshipsReference(signatureFactory, document, zipEntry
					.getName(), relsDocument, manifestReferences);
		}
	}

	private void addRelationshipsReference(
			XMLSignatureFactory signatureFactory, Document document,
			String zipEntryName, Document relsDocument,
			List<Reference> manifestReferences)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		LOG.debug("relationships: " + zipEntryName);
		RelationshipTransformParameterSpec parameterSpec = new RelationshipTransformParameterSpec();
		NodeList nodeList = relsDocument.getDocumentElement().getChildNodes();
		for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
			Node node = nodeList.item(nodeIdx);
			if (node.getNodeType() != Node.ELEMENT_NODE) {
				continue;
			}
			Element element = (Element) node;
			String relationshipType = element.getAttribute("Type");
			/*
			 * We skip some relationship types.
			 */
			if ("http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"
					.equals(relationshipType)) {
				continue;
			}
			if ("http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
					.equals(relationshipType)) {
				continue;
			}
			if ("http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin"
					.equals(relationshipType)) {
				continue;
			}
			if ("http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail"
					.equals(relationshipType)) {
				continue;
			}
			if ("http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps"
					.equals(relationshipType)) {
				continue;
			}
			if ("http://schemas.openxmlformats.org/officeDocument/2006/relationships/viewProps"
					.equals(relationshipType)) {
				continue;
			}
			String relationshipId = element.getAttribute("Id");
			parameterSpec.addRelationshipReference(relationshipId);
		}

		List<Transform> transforms = new LinkedList<Transform>();
		transforms.add(signatureFactory.newTransform(
				RelationshipTransformService.TRANSFORM_URI, parameterSpec));
		transforms.add(signatureFactory.newTransform(
				"http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
				(TransformParameterSpec) null));
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory
				.newReference(
						"/"
								+ zipEntryName
								+ "?ContentType=application/vnd.openxmlformats-package.relationships+xml",
						digestMethod, transforms, null, null);

		manifestReferences.add(reference);
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
		Document document = findDocument(zipEntryName);
		if (null != document) {
			return document;
		}
		throw new RuntimeException("ZIP entry not found: " + zipEntryName);
	}

	protected Document findDocument(String zipEntryName) throws IOException,
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
		return null;
	}

	private Document loadDocumentNoClose(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		NoCloseInputStream noCloseInputStream = new NoCloseInputStream(
				documentInputStream);
		InputSource inputSource = new InputSource(noCloseInputStream);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(inputSource);
		return document;
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
