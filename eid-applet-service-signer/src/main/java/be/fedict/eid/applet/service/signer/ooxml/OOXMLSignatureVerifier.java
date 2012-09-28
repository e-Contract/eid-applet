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

/*
 * Copyright (C) 2008-2009 FedICT.
 * This file is part of the eID Applet Project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package be.fedict.eid.applet.service.signer.ooxml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.KeyInfoKeySelector;
import be.fedict.eid.applet.service.signer.jaxb.opc.contenttypes.CTDefault;
import be.fedict.eid.applet.service.signer.jaxb.opc.contenttypes.CTOverride;
import be.fedict.eid.applet.service.signer.jaxb.opc.contenttypes.CTTypes;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationship;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationships;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.ObjectFactory;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.STTargetMode;

/**
 * Signature verifier util class for Office Open XML file format.
 * <p/>
 * Implementation according to: Office Open XML - Part 2: Open Packaging
 * Conventions - ECMA-376-2
 * 
 * @author Frank Cornelis
 */
public class OOXMLSignatureVerifier {

	private static final Log LOG = LogFactory
			.getLog(OOXMLSignatureVerifier.class);

	public static final String DIGITAL_SIGNATURE_ORIGIN_REL_TYPE = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";

	public static final String DIGITAL_SIGNATURE_REL_TYPE = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";

	private final Unmarshaller relationshipsUnmarshaller;

	public OOXMLSignatureVerifier() {
		try {
			JAXBContext relationshipsJAXBContext = JAXBContext
					.newInstance(ObjectFactory.class);
			this.relationshipsUnmarshaller = relationshipsJAXBContext
					.createUnmarshaller();
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
	}

	/**
	 * Checks whether the file referred by the given URL is an OOXML document.
	 * 
	 * @param url
	 * @return
	 * @throws IOException
	 */
	public static boolean isOOXML(URL url) throws IOException {
		ZipInputStream zipInputStream = new ZipInputStream(url.openStream());
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (false == "[Content_Types].xml".equals(zipEntry.getName())) {
				continue;
			}
			return true;
		}
		return false;
	}

	public List<X509Certificate> getSigners(URL url) throws IOException,
			ParserConfigurationException, SAXException, TransformerException,
			MarshalException, XMLSignatureException, JAXBException {
		List<X509Certificate> signers = new LinkedList<X509Certificate>();
		List<String> signatureResourceNames = getSignatureResourceNames(url);
		if (signatureResourceNames.isEmpty()) {
			LOG.debug("no signature resources");
		}
		for (String signatureResourceName : signatureResourceNames) {
			Document signatureDocument = getSignatureDocument(url,
					signatureResourceName);
			if (null == signatureDocument) {
				continue;
			}

			NodeList signatureNodeList = signatureDocument
					.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (0 == signatureNodeList.getLength()) {
				return null;
			}
			Node signatureNode = signatureNodeList.item(0);

			KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
			DOMValidateContext domValidateContext = new DOMValidateContext(
					keySelector, signatureNode);
			domValidateContext.setProperty(
					"org.jcp.xml.dsig.validateManifests", Boolean.TRUE);
			OOXMLURIDereferencer dereferencer = new OOXMLURIDereferencer(url);
			domValidateContext.setURIDereferencer(dereferencer);

			XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
					.getInstance();
			XMLSignature xmlSignature = xmlSignatureFactory
					.unmarshalXMLSignature(domValidateContext);
			boolean valid = xmlSignature.validate(domValidateContext);

			if (!valid) {
				LOG.debug("not a valid signature");
				continue;
			}

			/*
			 * Check the content of idPackageObject.
			 */
			List<XMLObject> objects = xmlSignature.getObjects();
			XMLObject idPackageObject = null;
			for (XMLObject object : objects) {
				if ("idPackageObject".equals(object.getId())) {
					idPackageObject = object;
					break;
				}
			}
			if (null == idPackageObject) {
				LOG.debug("idPackageObject ds:Object not present");
				continue;
			}
			List<XMLStructure> idPackageObjectContent = idPackageObject
					.getContent();
			Manifest idPackageObjectManifest = null;
			for (XMLStructure content : idPackageObjectContent) {
				if (content instanceof Manifest) {
					idPackageObjectManifest = (Manifest) content;
					break;
				}
			}
			if (null == idPackageObjectManifest) {
				LOG.debug("no ds:Manifest present within idPackageObject ds:Object");
				continue;
			}
			LOG.debug("ds:Manifest present within idPackageObject ds:Object");
			List<Reference> idPackageObjectReferences = idPackageObjectManifest
					.getReferences();
			Set<String> idPackageObjectReferenceUris = new HashSet<String>();
			Set<String> remainingIdPackageObjectReferenceUris = new HashSet<String>();
			for (Reference idPackageObjectReference : idPackageObjectReferences) {
				idPackageObjectReferenceUris.add(idPackageObjectReference
						.getURI());
				remainingIdPackageObjectReferenceUris
						.add(idPackageObjectReference.getURI());
			}
			LOG.debug("idPackageObject ds:Reference URIs: "
					+ idPackageObjectReferenceUris);
			CTTypes contentTypes = getContentTypes(url);
			List<String> relsEntryNames = getRelsEntryNames(url);
			for (String relsEntryName : relsEntryNames) {
				LOG.debug("---- relationship entry name: " + relsEntryName);
				CTRelationships relationships = getRelationships(url,
						relsEntryName);
				List<CTRelationship> relationshipList = relationships
						.getRelationship();
				boolean includeRelationshipInSignature = false;
				for (CTRelationship relationship : relationshipList) {
					String relationshipType = relationship.getType();
					STTargetMode targetMode = relationship.getTargetMode();
					if (null != targetMode) {
						LOG.debug("TargetMode: " + targetMode.name());
						if (targetMode == STTargetMode.EXTERNAL) {
							/*
							 * ECMA-376 Part 2 - 3rd edition
							 * 
							 * 13.2.4.16 Manifest Element
							 * 
							 * "The producer shall not create a Manifest element that references any data outside of the package."
							 */
							continue;
						}
					}
					if (false == OOXMLSignatureFacet
							.isSignedRelationship(relationshipType)) {
						continue;
					}
					String relationshipTarget = relationship.getTarget();
					String baseUri = "/"
							+ relsEntryName.substring(0,
									relsEntryName.indexOf("_rels/"));
					String streamEntry = baseUri + relationshipTarget;
					LOG.debug("stream entry: " + streamEntry);
					streamEntry = FilenameUtils.normalize(streamEntry);
					LOG.debug("normalized stream entry: " + streamEntry);
					String contentType = getContentType(contentTypes,
							streamEntry);
					if (relationshipType.endsWith("customXml")) {
						if (false == contentType.equals("inkml+xml")
								&& false == contentType.equals("text/xml")) {
							LOG.debug("skipping customXml with content type: "
									+ contentType);
							continue;
						}
					}
					includeRelationshipInSignature = true;
					LOG.debug("content type: " + contentType);
					String referenceUri = streamEntry + "?ContentType="
							+ contentType;
					LOG.debug("reference URI: " + referenceUri);
					if (false == idPackageObjectReferenceUris
							.contains(referenceUri)) {
						throw new RuntimeException(
								"no reference in idPackageObject ds:Object for relationship target: "
										+ streamEntry);
					}
					remainingIdPackageObjectReferenceUris.remove(referenceUri);
				}
				String relsReferenceUri = "/"
						+ relsEntryName
						+ "?ContentType=application/vnd.openxmlformats-package.relationships+xml";
				if (includeRelationshipInSignature
						&& false == idPackageObjectReferenceUris
								.contains(relsReferenceUri)) {
					LOG.debug("missing ds:Reference for: " + relsEntryName);
					throw new RuntimeException("missing ds:Reference for: "
							+ relsEntryName);
				}
				remainingIdPackageObjectReferenceUris.remove(relsReferenceUri);
			}
			if (false == remainingIdPackageObjectReferenceUris.isEmpty()) {
				LOG.debug("remaining idPackageObject reference URIs"
						+ idPackageObjectReferenceUris);
				throw new RuntimeException(
						"idPackageObject manifest contains unknown ds:References: "
								+ remainingIdPackageObjectReferenceUris);
			}

			X509Certificate signer = keySelector.getCertificate();
			signers.add(signer);
		}
		return signers;
	}

	private String getContentType(CTTypes contentTypes, String partName) {
		List<Object> defaultOrOverrideList = contentTypes
				.getDefaultOrOverride();
		for (Object defaultOrOverride : defaultOrOverrideList) {
			if (defaultOrOverride instanceof CTOverride) {
				CTOverride override = (CTOverride) defaultOrOverride;
				if (partName.equals(override.getPartName())) {
					return override.getContentType();
				}
			}
		}
		for (Object defaultOrOverride : defaultOrOverrideList) {
			if (defaultOrOverride instanceof CTDefault) {
				CTDefault ctDefault = (CTDefault) defaultOrOverride;
				if (partName.endsWith(ctDefault.getExtension())) {
					return ctDefault.getContentType();
				}
			}
		}
		return null;
	}

	private CTRelationships getRelationships(URL url,
			String relationshipsEntryName) throws IOException, JAXBException {
		ZipInputStream zipInputStream = new ZipInputStream(url.openStream());
		ZipEntry zipEntry;
		InputStream relationshipsInputStream = null;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (false == relationshipsEntryName.equals(zipEntry.getName())) {
				continue;
			}
			relationshipsInputStream = zipInputStream;
			break;
		}
		if (null == relationshipsInputStream) {
			return null;
		}
		JAXBContext jaxbContext = JAXBContext
				.newInstance(be.fedict.eid.applet.service.signer.jaxb.opc.relationships.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		JAXBElement<CTRelationships> relationshipsElement = (JAXBElement<CTRelationships>) unmarshaller
				.unmarshal(relationshipsInputStream);
		return relationshipsElement.getValue();
	}

	private List<String> getRelsEntryNames(URL url) throws IOException {
		List<String> relsEntryNames = new LinkedList<String>();
		ZipInputStream zipInputStream = new ZipInputStream(url.openStream());
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			String entryName = zipEntry.getName();
			if (entryName.endsWith(".rels")) {
				relsEntryNames.add(entryName);
			}
		}
		return relsEntryNames;
	}

	private CTTypes getContentTypes(URL url) throws IOException,
			ParserConfigurationException, SAXException, JAXBException {
		ZipInputStream zipInputStream = new ZipInputStream(url.openStream());
		ZipEntry zipEntry;
		InputStream contentTypesInputStream = null;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (!"[Content_Types].xml".equals(zipEntry.getName())) {
				continue;
			}
			contentTypesInputStream = zipInputStream;
			break;
		}
		if (null == contentTypesInputStream) {
			return null;
		}
		JAXBContext jaxbContext = JAXBContext
				.newInstance(be.fedict.eid.applet.service.signer.jaxb.opc.contenttypes.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		JAXBElement<CTTypes> contentTypesElement = (JAXBElement<CTTypes>) unmarshaller
				.unmarshal(contentTypesInputStream);
		return contentTypesElement.getValue();
	}

	public Document getSignatureDocument(URL url, String signatureResourceName)
			throws IOException, ParserConfigurationException, SAXException {
		return getSignatureDocument(url.openStream(), signatureResourceName);
	}

	public Document getSignatureDocument(InputStream documentInputStream,
			String signatureResourceName) throws IOException,
			ParserConfigurationException, SAXException {
		ZipInputStream zipInputStream = new ZipInputStream(documentInputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (!signatureResourceName.equals(zipEntry.getName())) {
				continue;
			}
			return OOXMLSignatureFacet.loadDocument(zipInputStream);
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public List<String> getSignatureResourceNames(byte[] document)
			throws IOException, JAXBException {
		List<String> signatureResourceNames = new LinkedList<String>();
		ZipInputStream zipInputStream = new ZipInputStream(
				new ByteArrayInputStream(document));
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if ("_rels/.rels".equals(zipEntry.getName())) {
				break;
			}
		}
		if (null == zipEntry) {
			LOG.debug("no _rels/.rels relationship part present");
			return signatureResourceNames;
		}

		String dsOriginPart = null;
		JAXBElement<CTRelationships> packageRelationshipsElement = (JAXBElement<CTRelationships>) this.relationshipsUnmarshaller
				.unmarshal(zipInputStream);
		CTRelationships packageRelationships = packageRelationshipsElement
				.getValue();
		List<CTRelationship> packageRelationshipList = packageRelationships
				.getRelationship();
		for (CTRelationship packageRelationship : packageRelationshipList) {
			if (DIGITAL_SIGNATURE_ORIGIN_REL_TYPE.equals(packageRelationship
					.getType())) {
				dsOriginPart = packageRelationship.getTarget();
				break;
			}
		}
		if (null == dsOriginPart) {
			LOG.debug("no Digital Signature Origin part present");
			return signatureResourceNames;
		}
		LOG.debug("Digital Signature Origin part: " + dsOriginPart);
		String dsOriginName = dsOriginPart.substring(dsOriginPart
				.lastIndexOf("/") + 1);
		LOG.debug("Digital Signature Origin base: " + dsOriginName);
		String dsOriginSegment = dsOriginPart.substring(0,
				dsOriginPart.lastIndexOf("/"))
				+ "/";
		LOG.debug("Digital Signature Origin segment: " + dsOriginSegment);
		String dsOriginRels = dsOriginSegment + "_rels/" + dsOriginName
				+ ".rels";
		LOG.debug("Digital Signature Origin relationship part: " + dsOriginRels);

		zipInputStream = new ZipInputStream(new ByteArrayInputStream(document));
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (dsOriginRels.equals(zipEntry.getName())) {
				break;
			}
		}
		if (null == zipEntry) {
			LOG.debug("no Digital Signature Origin relationship part present");
			return signatureResourceNames;
		}

		JAXBElement<CTRelationships> dsoRelationshipsElement = (JAXBElement<CTRelationships>) this.relationshipsUnmarshaller
				.unmarshal(zipInputStream);
		CTRelationships dsoRelationships = dsoRelationshipsElement.getValue();
		List<CTRelationship> dsoRelationshipList = dsoRelationships
				.getRelationship();
		for (CTRelationship dsoRelationship : dsoRelationshipList) {
			if (DIGITAL_SIGNATURE_REL_TYPE.equals(dsoRelationship.getType())) {
				String signatureResourceName = dsOriginSegment
						+ dsoRelationship.getTarget();
				signatureResourceNames.add(signatureResourceName);
			}
		}

		return signatureResourceNames;
	}

	@SuppressWarnings("unchecked")
	public boolean isValidOOXMLSignature(XMLSignature xmlSignature,
			byte[] document) throws IOException, TransformerException,
			SAXException, ParserConfigurationException {

		// check c18n == http://www.w3.org/TR/2001/REC-xml-c14n-20010315
		if (!xmlSignature.getSignedInfo().getCanonicalizationMethod()
				.getAlgorithm().equals(CanonicalizationMethod.INCLUSIVE)) {
			LOG.error("Invalid c18n method on OOXML Signature");
			return false;
		}

		List<Reference> refs = xmlSignature.getSignedInfo().getReferences();

		// check #idPackageObject reference
		Reference idPackageObjectRef = findReferenceFromURI(refs,
				"#idPackageObject");
		if (null == idPackageObjectRef) {
			LOG.error("No \"idPackageObject\" reference found!");
			return false;
		}

		// check idPackageObject element
		XMLObject idPackageObject = findObject(xmlSignature, "idPackageObject");
		if (null == idPackageObject) {
			LOG.error("No \"idPackageObject\" object found!");
			return false;
		}
		if (!isIdPackageObjectValid(xmlSignature.getId(), idPackageObject,
				document)) {
			LOG.error("Invalid \"idPackageObject\".");
			return false;
		}

		// check #idOfficeObject reference
		Reference idOfficeObjectRef = findReferenceFromURI(refs,
				"#idOfficeObject");
		if (null == idOfficeObjectRef) {
			LOG.error("No \"idOfficeObject\" reference found!");
			return false;
		}

		// check idOfficeObject element
		XMLObject idOfficeObject = findObject(xmlSignature, "idOfficeObject");
		if (null == idOfficeObject) {
			LOG.error("No \"idOfficeObject\" object found!");
			return false;
		}
		if (!isIdOfficeObjectValid(xmlSignature.getId(), idOfficeObject)) {
			LOG.error("Invalid \"idOfficeObject\".");
			return false;
		}

		return true;
	}

	@SuppressWarnings("unchecked")
	private boolean isIdOfficeObjectValid(String signatureId,
			XMLObject idOfficeObject) {

		SignatureProperties signatureProperties;
		if (1 != idOfficeObject.getContent().size()) {
			LOG.error("Expect SignatureProperties element in \"idPackageObject\".");
			return false;
		}
		signatureProperties = (SignatureProperties) idOfficeObject.getContent()
				.get(0);

		if (signatureProperties.getProperties().size() != 1) {
			LOG.error("Unexpected # of SignatureProperty's in idOfficeObject");
			return false;
		}

		// SignatureInfo
		SignatureProperty signatureInfoProperty = (SignatureProperty) signatureProperties
				.getProperties().get(0);
		if (!signatureInfoProperty.getId().equals("idOfficeV1Details")) {
			LOG.error("Unexpected SignatureProperty: expected id=idOfficeV1Details "
					+ "but got: " + signatureInfoProperty.getId());
			return false;
		}
		if (!signatureInfoProperty.getTarget().equals("#" + signatureId)) {
			LOG.error("Unexpected SignatureProperty: expected target=#"
					+ signatureId + " but got: "
					+ signatureInfoProperty.getTarget());
			LOG.warn("Allowing this error because of a bug in Office2010");
			// work-around for existing bug in Office2011
			// return false;
		}

		// SignatureInfoV1
		if (signatureInfoProperty.getContent().size() != 1) {
			LOG.error("Unexpected content in SignatureInfoProperty.");
			return false;
		}
		DOMStructure signatureInfoV1DOM = (DOMStructure) signatureInfoProperty
				.getContent().get(0);
		Node signatureInfoElement = signatureInfoV1DOM.getNode();
		if (!signatureInfoElement.getNamespaceURI().equals(
				OOXMLSignatureFacet.OFFICE_DIGSIG_NS)) {
			LOG.error("Unexpected SignatureInfoProperty content: NS="
					+ signatureInfoElement.getNamespaceURI());
			return false;
		}

		// TODO: validate childs: validate all possible from 2.5.2.5
		// ([MS-OFFCRYPTO]) or just ManifestHashAlgorithm?

		return true;
	}

	@SuppressWarnings("unchecked")
	private boolean isIdPackageObjectValid(String signatureId,
			XMLObject idPackageObject, byte[] document) throws IOException,
			TransformerException, SAXException, ParserConfigurationException {

		Manifest manifest;
		SignatureProperties signatureProperties;
		if (2 != idPackageObject.getContent().size()) {
			LOG.error("Expect Manifest + SignatureProperties elements in \"idPackageObject\".");
			return false;
		}
		manifest = (Manifest) idPackageObject.getContent().get(0);
		signatureProperties = (SignatureProperties) idPackageObject
				.getContent().get(1);

		// Manifest
		List<Reference> refs = manifest.getReferences();
		ByteArrayInputStream bais = new ByteArrayInputStream(document);
		ZipInputStream zipInputStream = new ZipInputStream(bais);
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {

			if (validZipEntryStream(zipEntry.getName())) {
				// check relationship refs
				String relationshipReferenceURI = OOXMLSignatureFacet
						.getRelationshipReferenceURI(zipEntry.getName());
				if (null == findReferenceFromURI(refs, relationshipReferenceURI)) {
					LOG.error("Did not find relationship ref: \""
							+ relationshipReferenceURI + "\"");
					return false;
				}
			}
		}

		// check streams signed
		for (Map.Entry<String, String> resourceEntry : getResources(document)
				.entrySet()) {

			String resourceReferenceURI = OOXMLSignatureFacet
					.getResourceReferenceURI(resourceEntry.getKey(),
							resourceEntry.getValue());
			if (null == findReferenceFromURI(refs, resourceReferenceURI)) {
				LOG.error("Did not find resource ref: \""
						+ resourceReferenceURI + "\"");
				return false;
			}
		}

		// SignatureProperties
		if (signatureProperties.getProperties().size() != 1) {
			LOG.error("Unexpected # of SignatureProperty's in idPackageObject");
			return false;
		}
		if (!validateSignatureProperty((SignatureProperty) signatureProperties
				.getProperties().get(0), signatureId)) {
			return false;
		}

		return true;
	}

	@SuppressWarnings("unchecked")
	private boolean validateSignatureProperty(
			SignatureProperty signatureProperty, String signatureId) {

		if (!signatureProperty.getId().equals("idSignatureTime")) {
			LOG.error("Unexpected SignatureProperty: expected id=idSignatureTime "
					+ "but got: " + signatureProperty.getId());
			return false;
		}
		if (!signatureProperty.getTarget().equals("#" + signatureId)) {
			LOG.error("Unexpected SignatureProperty: expected target=#"
					+ signatureId + "but got: " + signatureProperty.getTarget());
			return false;
		}
		List<XMLStructure> signatureTimeContent = signatureProperty
				.getContent();
		if (signatureTimeContent.size() != 1) {
			LOG.error("Unexpected SignatureTime content.");
			return false;
		}
		DOMStructure signatureTimeDOM = (DOMStructure) signatureTimeContent
				.get(0);
		Node signatureTimeElement = signatureTimeDOM.getNode();
		if (!signatureTimeElement.getNamespaceURI().equals(
				OOXMLSignatureFacet.OOXML_DIGSIG_NS)) {
			LOG.error("Invalid SignatureTime element: NS="
					+ signatureTimeElement.getNamespaceURI());
			return false;
		}
		if (!signatureTimeElement.getLocalName().equals("SignatureTime")) {
			LOG.error("Invalid SignatureTime element: Name="
					+ signatureTimeElement.getLocalName());
			return false;
		}
		if (signatureTimeElement.getChildNodes().getLength() != 2) {
			LOG.error("Invalid SignatureTime element: Childs="
					+ signatureTimeElement.getChildNodes().getLength()
					+ ", expected 2 (Format+Value)");
			return false;
		}

		// format element
		Node formatElement = signatureTimeElement.getChildNodes().item(0);
		if (!formatElement.getNamespaceURI().equals(
				OOXMLSignatureFacet.OOXML_DIGSIG_NS)) {
			LOG.error("Invalid SignatureTime.Format element: NS="
					+ formatElement.getNamespaceURI());
			return false;
		}
		if (!formatElement.getLocalName().equals("Format")) {
			LOG.error("Invalid SignatureTime.Format element: Name="
					+ formatElement.getLocalName());
			return false;
		}

		// value element
		Node valueElement = signatureTimeElement.getChildNodes().item(1);
		if (!valueElement.getNamespaceURI().equals(
				OOXMLSignatureFacet.OOXML_DIGSIG_NS)) {
			LOG.error("Invalid SignatureTime.Value element: NS="
					+ valueElement.getNamespaceURI());
			return false;
		}
		if (!valueElement.getLocalName().equals("Value")) {
			LOG.error("Invalid SignatureTime.Value element: Name="
					+ valueElement.getLocalName());
			return false;
		}

		// TODO: validate value?

		return true;
	}

	private boolean validZipEntryStream(String zipEntryName) {

		if (!zipEntryName.endsWith(".rels")) {
			return false;
		}

		for (String excludedStream : excludedStreams) {
			if (zipEntryName.startsWith(excludedStream + "/")) {
				return false;
			}
		}
		return true;
	}

	// returns map of <partName,contentType> entries of the document
	private Map<String, String> getResources(byte[] document)
			throws IOException, ParserConfigurationException, SAXException,
			TransformerException {

		Map<String, String> signatureResources = new HashMap<String, String>();

		ByteArrayInputStream bais = new ByteArrayInputStream(document);
		ZipInputStream zipInputStream = new ZipInputStream(bais);
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (!"[Content_Types].xml".equals(zipEntry.getName())) {
				continue;
			}
			Document contentTypesDocument = OOXMLSignatureFacet
					.loadDocument(zipInputStream);
			Element nsElement = contentTypesDocument.createElement("ns");
			nsElement
					.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:tns",
							"http://schemas.openxmlformats.org/package/2006/content-types");

			for (String contentType : OOXMLSignatureFacet.contentTypes) {
				NodeList nodeList = XPathAPI.selectNodeList(
						contentTypesDocument,
						"/tns:Types/tns:Override[@ContentType='" + contentType
								+ "']/@PartName", nsElement);
				for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
					String partName = nodeList.item(nodeIdx).getTextContent();
					LOG.debug("part name: " + partName);
					partName = partName.substring(1); // remove '/'
					signatureResources.put(partName, contentType);
				}
			}
			break;
		}
		return signatureResources;
	}

	@SuppressWarnings("unchecked")
	private XMLObject findObject(XMLSignature xmlSignature, String objectId) {

		List<XMLObject> objects = xmlSignature.getObjects();
		for (XMLObject object : objects) {
			if (objectId.equals(object.getId())) {
				LOG.debug("Found \"" + objectId + "\" ds:object");
				return object;
			}
		}
		return null;
	}

	private Reference findReferenceFromURI(List<Reference> refs,
			String referenceURI) {

		for (Reference ref : refs) {
			if (ref.getURI().equals(referenceURI)) {
				LOG.debug("Found \"" + referenceURI + "\" ds:reference");
				return ref;
			}
		}
		return null;
	}

	public List<String> getSignatureResourceNames(URL url) throws IOException,
			ParserConfigurationException, SAXException, TransformerException,
			JAXBException {
		byte[] document = IOUtils.toByteArray(url.openStream());
		return getSignatureResourceNames(document);
	}

	public static String[] excludedStreams = {

	"0x05Bagaaqy23kudbhchAaq5u2chNd", "0x06DataSpaces", "Xmlsignatures",
			"MsoDataStore", "0x09DRMContent", "_signatures", "_xmlsignatures",
			"0x05SummaryInformation", "0x05DocumentSummaryInformation" };
}
