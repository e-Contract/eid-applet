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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
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

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.jaxb.opc.contenttypes.CTDefault;
import be.fedict.eid.applet.service.signer.jaxb.opc.contenttypes.CTOverride;
import be.fedict.eid.applet.service.signer.jaxb.opc.contenttypes.CTTypes;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationship;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationships;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.STTargetMode;
import be.fedict.eid.applet.service.signer.time.Clock;
import be.fedict.eid.applet.service.signer.time.LocalClock;

/**
 * Office OpenXML Signature Facet implementation.
 * 
 * @author fcorneli
 * @see http://msdn.microsoft.com/en-us/library/cc313071.aspx
 */
public class OOXMLSignatureFacet implements SignatureFacet {

	private static final Log LOG = LogFactory.getLog(OOXMLSignatureFacet.class);

	public static final String OOXML_DIGSIG_NS = "http://schemas.openxmlformats.org/package/2006/digital-signature";
	public static final String OFFICE_DIGSIG_NS = "http://schemas.microsoft.com/office/2006/digsig";

	private final AbstractOOXMLSignatureService signatureService;

	private final Clock clock;

	private final DigestAlgo digestAlgo;

	/**
	 * Main constructor.
	 */
	public OOXMLSignatureFacet(AbstractOOXMLSignatureService signatureService) {
		this(signatureService, new LocalClock(), DigestAlgo.SHA1);
	}

	/**
	 * Main constructor.
	 */
	public OOXMLSignatureFacet(AbstractOOXMLSignatureService signatureService,
			Clock clock, DigestAlgo digestAlgo) {
		this.signatureService = signatureService;
		this.clock = clock;
		this.digestAlgo = digestAlgo;
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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
				this.digestAlgo.getXmlAlgoId(), null);
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
			addManifestReferences(signatureFactory, document,
					manifestReferences);
		} catch (Exception e) {
			throw new RuntimeException("error: " + e.getMessage(), e);
		}

		return signatureFactory.newManifest(manifestReferences);
	}

	private void addManifestReferences(XMLSignatureFactory signatureFactory,
			Document document, List<Reference> manifestReferences)
			throws IOException, JAXBException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		CTTypes contentTypes = getContentTypes();
		List<String> relsEntryNames = getRelsEntryNames();
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				this.digestAlgo.getXmlAlgoId(), null);
		Set<String> digestedPartNames = new HashSet<String>();
		for (String relsEntryName : relsEntryNames) {
			CTRelationships relationships = getRelationships(relsEntryName);
			List<CTRelationship> relationshipList = relationships
					.getRelationship();
			RelationshipTransformParameterSpec parameterSpec = new RelationshipTransformParameterSpec();
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
				String baseUri = "/"
						+ relsEntryName.substring(0,
								relsEntryName.indexOf("_rels/"));
				String relationshipTarget = relationship.getTarget();
				String partName = FilenameUtils.separatorsToUnix( 
						FilenameUtils.normalize(baseUri
						+ relationshipTarget));
				LOG.debug("part name: " + partName);
				String relationshipId = relationship.getId();
				parameterSpec.addRelationshipReference(relationshipId);
				String contentType = getContentType(contentTypes, partName);
				if (relationshipType.endsWith("customXml")) {
					if (false == contentType.equals("inkml+xml")
							&& false == contentType.equals("text/xml")) {
						LOG.debug("skipping customXml with content type: "
								+ contentType);
						continue;
					}
				}
				if (false == digestedPartNames.contains(partName)) {
					/*
					 * We only digest a part once.
					 */
					Reference reference = signatureFactory.newReference(
							partName + "?ContentType=" + contentType,
							digestMethod);
					manifestReferences.add(reference);
					digestedPartNames.add(partName);
				}
			}
			if (false == parameterSpec.getSourceIds().isEmpty()) {
				List<Transform> transforms = new LinkedList<Transform>();
				transforms.add(signatureFactory.newTransform(
						RelationshipTransformService.TRANSFORM_URI,
						parameterSpec));
				transforms.add(signatureFactory.newTransform(
						CanonicalizationMethod.INCLUSIVE,
						(TransformParameterSpec) null));
				Reference reference = signatureFactory
						.newReference(
								"/"
										+ relsEntryName
										+ "?ContentType=application/vnd.openxmlformats-package.relationships+xml",
								digestMethod, transforms, null, null);

				manifestReferences.add(reference);
			}
		}
	}

	/**
	 * According to ECMA-376, Part 2. 10.1.2 Mapping Content Types.
	 * 
	 * @param contentTypes
	 * @param partName
	 * @return
	 */
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

	private CTRelationships getRelationships(String relsEntryName)
			throws IOException, JAXBException {
		URL ooxmlUrl = this.signatureService.getOfficeOpenXMLDocumentURL();
		ZipInputStream zipInputStream = new ZipInputStream(
				ooxmlUrl.openStream());
		ZipEntry zipEntry;
		InputStream relationshipsInputStream = null;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (false == relsEntryName.equals(zipEntry.getName())) {
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

	private CTTypes getContentTypes() throws IOException, JAXBException {
		URL ooxmlUrl = this.signatureService.getOfficeOpenXMLDocumentURL();
		ZipInputStream zipInputStream = new ZipInputStream(
				ooxmlUrl.openStream());
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

	private List<String> getRelsEntryNames() throws IOException {
		List<String> relsEntryNames = new LinkedList<String>();
		URL ooxmlUrl = this.signatureService.getOfficeOpenXMLDocumentURL();
		InputStream inputStream = ooxmlUrl.openStream();
		ZipInputStream zipInputStream = new ZipInputStream(inputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			String zipEntryName = zipEntry.getName();
			if (false == zipEntryName.endsWith(".rels")) {
				continue;
			}
			relsEntryNames.add(zipEntryName);
		}
		return relsEntryNames;
	}

	private void addSignatureTime(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<XMLStructure> objectContent) {
		/*
		 * SignatureTime
		 */
		Element signatureTimeElement = document.createElementNS(
				OOXML_DIGSIG_NS, "mdssi:SignatureTime");
		signatureTimeElement.setAttributeNS(Constants.NamespaceSpecNS,
				"xmlns:mdssi", OOXML_DIGSIG_NS);
		Element formatElement = document.createElementNS(OOXML_DIGSIG_NS,
				"mdssi:Format");
		formatElement.setTextContent("YYYY-MM-DDThh:mm:ssTZD");
		signatureTimeElement.appendChild(formatElement);
		Element valueElement = document.createElementNS(OOXML_DIGSIG_NS,
				"mdssi:Value");
		Date now = this.clock.getTime();
		DateTime dateTime = new DateTime(now.getTime(), DateTimeZone.UTC);
		DateTimeFormatter fmt = ISODateTimeFormat.dateTimeNoMillis();
		String nowStr = fmt.print(dateTime);
		LOG.debug("now: " + nowStr);
		valueElement.setTextContent(nowStr);
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
				OFFICE_DIGSIG_NS, "SignatureInfoV1");
		signatureInfoElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns",
				OFFICE_DIGSIG_NS);

		Element manifestHashAlgorithmElement = document.createElementNS(
				OFFICE_DIGSIG_NS, "ManifestHashAlgorithm");
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
				this.digestAlgo.getXmlAlgoId(), null);
		Reference reference = signatureFactory.newReference("#" + objectId,
				digestMethod, null, "http://www.w3.org/2000/09/xmldsig#Object",
				null);
		references.add(reference);
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

	public static Document loadDocument(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		InputSource inputSource = new InputSource(documentInputStream);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		return documentBuilder.parse(inputSource);
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}

	public static String getRelationshipReferenceURI(String zipEntryName) {

		return "/"
				+ zipEntryName
				+ "?ContentType=application/vnd.openxmlformats-package.relationships+xml";
	}

	public static String getResourceReferenceURI(String resourceName,
			String contentType) {

		return "/" + resourceName + "?ContentType=" + contentType;
	}

	public static String[] contentTypes = {

			/*
			 * Word
			 */
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
			"application/vnd.openxmlformats-officedocument.theme+xml",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml",

			/*
			 * Word 2010
			 */
			"application/vnd.ms-word.stylesWithEffects+xml",

			/*
			 * Excel
			 */
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",

			/*
			 * Powerpoint
			 */
			"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
			"application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
			"application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
			"application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
			"application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml",

			/*
			 * Powerpoint 2010
			 */
			"application/vnd.openxmlformats-officedocument.presentationml.viewProps+xml",
			"application/vnd.openxmlformats-officedocument.presentationml.presProps+xml" };

	public static boolean isSignedRelationship(String relationshipType) {
		LOG.debug("relationship type: " + relationshipType);
		for (String signedTypeExtension : signed) {
			if (relationshipType.endsWith(signedTypeExtension)) {
				return true;
			}
		}
		if (relationshipType.endsWith("customXml")) {
			LOG.debug("customXml relationship type");
			return true;
		}
		return false;
	}

	/**
	 * Office 2010 list of signed types (extensions).
	 */
	public static String[] signed = { "powerPivotData", //
			"activeXControlBinary", //
			"attachedToolbars", //
			"connectorXml", //
			"downRev", //
			"functionPrototypes", //
			"graphicFrameDoc", //
			"groupShapeXml", //
			"ink", //
			"keyMapCustomizations", //
			"legacyDiagramText", //
			"legacyDocTextInfo", //
			"officeDocument", //
			"pictureXml", //
			"shapeXml", //
			"smartTags", //
			"ui/altText", //
			"ui/buttonSize", //
			"ui/controlID", //
			"ui/description", //
			"ui/enabled", //
			"ui/extensibility", //
			"ui/helperText", //
			"ui/imageID", //
			"ui/imageMso", //
			"ui/keyTip", //
			"ui/label", //
			"ui/lcid", //
			"ui/loud", //
			"ui/pressed", //
			"ui/progID", //
			"ui/ribbonID", //
			"ui/showImage", //
			"ui/showLabel", //
			"ui/supertip", //
			"ui/target", //
			"ui/text", //
			"ui/title", //
			"ui/tooltip", //
			"ui/userCustomization", //
			"ui/visible", //
			"userXmlData", //
			"vbaProject", //
			"wordVbaData", //
			"wsSortMap", //
			"xlBinaryIndex", //
			"xlExternalLinkPath/xlAlternateStartup", //
			"xlExternalLinkPath/xlLibrary", //
			"xlExternalLinkPath/xlPathMissing", //
			"xlExternalLinkPath/xlStartup", //
			"xlIntlMacrosheet", //
			"xlMacrosheet", //
			"customData", //
			"diagramDrawing", //
			"hdphoto", //
			"inkXml", //
			"media", //
			"slicer", //
			"slicerCache", //
			"stylesWithEffects", //
			"ui/extensibility", //
			"chartColorStyle", //
			"chartLayout", //
			"chartStyle", //
			"dictionary", //
			"timeline", //
			"timelineCache", //
			"aFChunk", //
			"attachedTemplate", //
			"audio", //
			"calcChain", //
			"chart", //
			"chartsheet", //
			"chartUserShapes", //
			"commentAuthors", //
			"comments", //
			"connections", //
			"control", //
			"customProperty", //
			"customXml", //
			"diagramColors", //
			"diagramData", //
			"diagramLayout", //
			"diagramQuickStyle", //
			"dialogsheet", //
			"drawing", //
			"endnotes", //
			"externalLink", //
			"externalLinkPath", //
			"font", //
			"fontTable", //
			"footer", //
			"footnotes", //
			"glossaryDocument", //
			"handoutMaster", //
			"header", //
			"hyperlink", //
			"image", //
			"mailMergeHeaderSource", //
			"mailMergeRecipientData", //
			"mailMergeSource", //
			"notesMaster", //
			"notesSlide", //
			"numbering", //
			"officeDocument", //
			"oleObject", //
			"package", //
			"pivotCacheDefinition", //
			"pivotCacheRecords", //
			"pivotTable", //
			"presProps", //
			"printerSettings", //
			"queryTable", //
			"recipientData", //
			"settings", //
			"sharedStrings", //
			"sheetMetadata", //
			"slide", //
			"slideLayout", //
			"slideMaster", //
			"slideUpdateInfo", //
			"slideUpdateUrl", //
			"styles", //
			"table", //
			"tableSingleCells", //
			"tableStyles", //
			"tags", //
			"theme", //
			"themeOverride", //
			"transform", //
			"video", //
			"viewProps", //
			"volatileDependencies", //
			"webSettings", //
			"worksheet", //
			"xmlMaps", //
			"ctrlProp", //
			"customData", //
			"diagram", //
			"diagramColorsHeader", //
			"diagramLayoutHeader", //
			"diagramQuickStyleHeader", //
			"documentParts", //
			"slicer", //
			"slicerCache", //
			"vmlDrawing" //
	};
}
