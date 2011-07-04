/*
 * eID Applet Project.
 * Copyright (C) 2011 FedICT.
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

package be.fedict.eid.applet.service.signer.asic;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.KeyInfoKeySelector;
import be.fedict.eid.applet.service.signer.odf.ODFUtil;

public class ASiCSignatureVerifier {

	private ASiCSignatureVerifier() {
		super();
	}

	public static List<X509Certificate> verifySignatures(byte[] asicDocument)
			throws IOException, ParserConfigurationException, SAXException,
			MarshalException, XMLSignatureException {
		ZipInputStream zipInputStream = new ZipInputStream(
				new ByteArrayInputStream(asicDocument));
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (ASiCUtil.isSignatureZipEntry(zipEntry)) {
				break;
			}
		}
		List<X509Certificate> signatories = new LinkedList<X509Certificate>();
		if (null == zipEntry) {
			return signatories;
		}

		Document documentSignaturesDocument = ODFUtil
				.loadDocument(zipInputStream);
		NodeList signatureNodeList = documentSignaturesDocument
				.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		for (int idx = 0; idx < signatureNodeList.getLength(); idx++) {
			Element signatureElement = (Element) signatureNodeList.item(idx);
			KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
			DOMValidateContext domValidateContext = new DOMValidateContext(
					keySelector, signatureElement);
			ASiCURIDereferencer dereferencer = new ASiCURIDereferencer(
					asicDocument);
			domValidateContext.setURIDereferencer(dereferencer);

			XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
					.getInstance();
			XMLSignature xmlSignature = xmlSignatureFactory
					.unmarshalXMLSignature(domValidateContext);
			boolean valid = xmlSignature.validate(domValidateContext);
			if (!valid) {
				continue;
			}
			X509Certificate signer = keySelector.getCertificate();
			signatories.add(signer);
		}
		return signatories;
	}
}
