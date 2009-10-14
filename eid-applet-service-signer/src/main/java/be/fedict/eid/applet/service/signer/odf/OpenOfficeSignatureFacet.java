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

package be.fedict.eid.applet.service.signer.odf;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.fedict.eid.applet.service.signer.SignatureFacet;

/**
 * OpenOffice.org signature facet.
 * 
 * @author fcorneli
 * 
 */
public class OpenOfficeSignatureFacet implements SignatureFacet {

	private static final Log LOG = LogFactory
			.getLog(OpenOfficeSignatureFacet.class);

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId, List<Reference> references,
			List<XMLObject> objects) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		LOG.debug("pre sign");

		Element dateElement = document.createElementNS("", "dc:date");
		dateElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:dc",
				"http://purl.org/dc/elements/1.1/");
		DateTime dateTime = new DateTime(DateTimeZone.UTC);
		DateTimeFormatter fmt = ISODateTimeFormat.dateTimeNoMillis();
		String now = fmt.print(dateTime);
		now = now.substring(0, now.indexOf("Z"));
		LOG.debug("now: " + now);
		dateElement.setTextContent(now);

		String signaturePropertyId = "sign-prop-"
				+ UUID.randomUUID().toString();
		List<XMLStructure> signaturePropertyContent = new LinkedList<XMLStructure>();
		signaturePropertyContent.add(new DOMStructure(dateElement));
		SignatureProperty signatureProperty = signatureFactory
				.newSignatureProperty(signaturePropertyContent, "#"
						+ signatureId, signaturePropertyId);

		List<XMLStructure> objectContent = new LinkedList<XMLStructure>();
		List<SignatureProperty> signaturePropertiesContent = new LinkedList<SignatureProperty>();
		signaturePropertiesContent.add(signatureProperty);
		SignatureProperties signatureProperties = signatureFactory
				.newSignatureProperties(signaturePropertiesContent, null);
		objectContent.add(signatureProperties);

		objects.add(signatureFactory.newXMLObject(objectContent, null, null,
				null));

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		Reference reference = signatureFactory.newReference("#"
				+ signaturePropertyId, digestMethod);
		references.add(reference);
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}
}
