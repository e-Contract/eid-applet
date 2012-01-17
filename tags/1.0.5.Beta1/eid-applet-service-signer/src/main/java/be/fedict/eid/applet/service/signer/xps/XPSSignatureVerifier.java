/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

package be.fedict.eid.applet.service.signer.xps;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

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

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationship;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationships;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.ObjectFactory;
import be.fedict.eid.applet.service.signer.ooxml.OOXMLSignatureVerifier;
import be.fedict.eid.applet.service.signer.ooxml.OOXMLURIDereferencer;
import be.fedict.eid.applet.service.signer.ooxml.OPCKeySelector;

/**
 * Simple signature verifier for the Open XML Paper Specification.
 * 
 * Implementation according to: Office Open XML - Part 2: Open Packaging
 * Conventions - ECMA-376-2
 * 
 * @author Frank Cornelis
 * 
 */
public class XPSSignatureVerifier {

	private static final Log LOG = LogFactory
			.getLog(XPSSignatureVerifier.class);

	private final Unmarshaller relationshipsUnmarshaller;

	public XPSSignatureVerifier() {
		try {
			JAXBContext relationshipsJAXBContext = JAXBContext
					.newInstance(ObjectFactory.class);
			this.relationshipsUnmarshaller = relationshipsJAXBContext
					.createUnmarshaller();
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
	}

	public List<X509Certificate> getSigners(URL url) throws IOException,
			ParserConfigurationException, SAXException, TransformerException,
			MarshalException, XMLSignatureException, JAXBException {
		List<X509Certificate> signers = new LinkedList<X509Certificate>();
		List<String> signatureResourceNames = getSignatureResourceNames(url);
		for (String signatureResourceName : signatureResourceNames) {
			LOG.debug("signature resource name: " + signatureResourceName);
			Document signatureDocument = loadDocument(url,
					signatureResourceName);
			if (null == signatureDocument) {
				LOG.warn("signature resource not found: "
						+ signatureResourceName);
				continue;
			}

			NodeList signatureNodeList = signatureDocument
					.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
			if (0 == signatureNodeList.getLength()) {
				LOG.debug("no signature elements present");
				continue;
			}
			Node signatureNode = signatureNodeList.item(0);

			OPCKeySelector keySelector = new OPCKeySelector(url,
					signatureResourceName);
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

	private Document loadDocument(URL url, String signatureResourceName)
			throws IOException, ParserConfigurationException, SAXException {
		ZipArchiveInputStream zipInputStream = new ZipArchiveInputStream(
				url.openStream(), "UTF8", true, true);
		ZipArchiveEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextZipEntry())) {
			if (false == signatureResourceName.equals(zipEntry.getName())) {
				continue;
			}
			Document document = loadDocument(zipInputStream);
			return document;
		}
		return null;
	}

	private List<String> getSignatureResourceNames(URL url) throws IOException,
			ParserConfigurationException, SAXException, TransformerException,
			JAXBException {
		List<String> signatureResourceNames = new LinkedList<String>();
		ZipArchiveInputStream zipInputStream = new ZipArchiveInputStream(
				url.openStream(), "UTF8", true, true);
		ZipArchiveEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextZipEntry())) {
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
			if (OOXMLSignatureVerifier.DIGITAL_SIGNATURE_ORIGIN_REL_TYPE
					.equals(packageRelationship.getType())) {
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
		if (dsOriginRels.startsWith("/")) {
			dsOriginRels = dsOriginRels.substring(1);
		}

		zipInputStream = new ZipArchiveInputStream(url.openStream(), "UTF8",
				true, true);
		while (null != (zipEntry = zipInputStream.getNextZipEntry())) {
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
			if (OOXMLSignatureVerifier.DIGITAL_SIGNATURE_REL_TYPE
					.equals(dsoRelationship.getType())) {
				String signatureResourceName;
				if (dsoRelationship.getTarget().startsWith("/")) {
					signatureResourceName = dsoRelationship.getTarget();
				} else {
					signatureResourceName = dsOriginSegment
							+ dsoRelationship.getTarget();
				}
				if (signatureResourceName.startsWith("/")) {
					signatureResourceName = signatureResourceName.substring(1);
				}
				LOG.debug("signature resource name: " + signatureResourceName);
				signatureResourceNames.add(signatureResourceName);
			}
		}

		return signatureResourceNames;
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
