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
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.KeyInfoKeySelector;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationship;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationships;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.ObjectFactory;

/**
 * Signature verifier util class for Office Open XML file format.
 * 
 * Implementation according to: Office Open XML - Part 2: Open Packaging
 * Conventions - ECMA-376-2
 * 
 * @author Frank Cornelis
 * 
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
			boolean validity = xmlSignature.validate(domValidateContext);

			if (false == validity) {
				LOG.debug("not a valid signature");
				continue;
			}
			// TODO: check what has been signed.

			X509Certificate signer = keySelector.getCertificate();
			signers.add(signer);
		}
		return signers;
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
			if (false == signatureResourceName.equals(zipEntry.getName())) {
				continue;
			}
			Document signatureDocument = loadDocument(zipInputStream);
			return signatureDocument;
		}
		return null;
	}

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

	public List<String> getSignatureResourceNames(URL url) throws IOException,
			ParserConfigurationException, SAXException, TransformerException,
			JAXBException {
		byte[] document = IOUtils.toByteArray(url.openStream());
		return getSignatureResourceNames(document);
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
