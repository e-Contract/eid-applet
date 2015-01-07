/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
 * Copyright (C) 2015 e-Contract.be BVBA.
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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.transform.TransformerException;

import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.facets.XAdESXLSignatureFacet;

/**
 * Work-around for Office2010 to accept the XAdES-BES/EPES signature.
 * 
 * xades:UnsignedProperties/xades:UnsignedSignatureProperties needs to be
 * present.
 * 
 * @author Frank Cornelis
 * 
 */
public class Office2010SignatureFacet implements SignatureFacet {

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		Document document = signatureElement.getOwnerDocument();
		Element nsElement = document.createElement("nsElement");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				Constants.SignatureSpecNS);
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xades",
				XAdESXLSignatureFacet.XADES_NAMESPACE);
		Element qualifyingPropertiesElement;
		try {
			qualifyingPropertiesElement = (Element) XPathAPI.selectSingleNode(
					signatureElement, "ds:Object/xades:QualifyingProperties",
					nsElement);
		} catch (TransformerException e) {
			throw new RuntimeException("XPath error: " + e.getMessage(), e);
		}
		String namespacePrefix = qualifyingPropertiesElement.getPrefix();
		if (null == namespacePrefix || namespacePrefix.isEmpty()) {
			namespacePrefix = "";
		} else {
			namespacePrefix = namespacePrefix + ":";
		}
		Element unsignedPropertiesElement = document.createElementNS(
				XAdESXLSignatureFacet.XADES_NAMESPACE, namespacePrefix
						+ "UnsignedProperties");
		qualifyingPropertiesElement.appendChild(unsignedPropertiesElement);
		Element unsignedSignaturePropertiesElement = document.createElementNS(
				XAdESXLSignatureFacet.XADES_NAMESPACE, namespacePrefix
						+ "UnsignedSignatureProperties");
		unsignedPropertiesElement
				.appendChild(unsignedSignaturePropertiesElement);
	}
}
