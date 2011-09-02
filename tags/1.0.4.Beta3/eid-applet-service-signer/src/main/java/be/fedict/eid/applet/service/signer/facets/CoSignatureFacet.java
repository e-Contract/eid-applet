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

package be.fedict.eid.applet.service.signer.facets;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.fedict.eid.applet.service.signer.SignatureFacet;

/**
 * Signature facet to create multiple independent signatures, a.k.a
 * co-signatures.
 * 
 * @author Frank Cornelis
 * 
 */
public class CoSignatureFacet implements SignatureFacet {

	private final DigestAlgo digestAlgo;

	/**
	 * Default constructor. Digest algorithm will be SHA-1.
	 */
	public CoSignatureFacet() {
		this(DigestAlgo.SHA1);
	}

	/**
	 * Main constructor.
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used within the ds:Reference
	 *            element. Possible values: "SHA-1", "SHA-256, or "SHA-512".
	 */
	public CoSignatureFacet(DigestAlgo digestAlgorithm) {
		this.digestAlgo = digestAlgorithm;
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				this.digestAlgo.getXmlAlgoId(), null);

		List<Transform> transforms = new LinkedList<Transform>();
		Map<String, String> xpathNamespaceMap = new HashMap<String, String>();
		xpathNamespaceMap.put("ds", "http://www.w3.org/2000/09/xmldsig#");
		Transform envelopedTransform = signatureFactory.newTransform(
				CanonicalizationMethod.XPATH, new XPathFilterParameterSpec(
						"not(ancestor-or-self::ds:Signature)",
						xpathNamespaceMap));
		transforms.add(envelopedTransform);
		Transform exclusiveTransform = signatureFactory
				.newTransform(CanonicalizationMethod.EXCLUSIVE,
						(TransformParameterSpec) null);
		transforms.add(exclusiveTransform);

		Reference reference = signatureFactory.newReference("", digestMethod,
				transforms, null, null);

		references.add(reference);
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}
}
