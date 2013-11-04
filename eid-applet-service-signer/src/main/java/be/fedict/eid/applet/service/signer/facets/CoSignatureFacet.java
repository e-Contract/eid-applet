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

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Signature facet to create multiple independent signatures, a.k.a
 * co-signatures.
 * 
 * @author Frank Cornelis
 * 
 */
public class CoSignatureFacet implements SignatureFacet {

	private final DigestAlgo digestAlgo;

	private final String dsReferenceId;

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
		this(digestAlgorithm, "");
	}

	/**
	 * Main constructor.
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used within the ds:Reference
	 *            element. Possible values: "SHA-1", "SHA-256, or "SHA-512".
	 * @param dsReferenceId
	 *            the optional Id to be used on the ds:Reference element.
	 */
	public CoSignatureFacet(DigestAlgo digestAlgorithm, String dsReferenceId) {
		this.digestAlgo = digestAlgorithm;
		this.dsReferenceId = dsReferenceId;
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

        // XPath v1 - slow...
//		Transform envelopedTransform = signatureFactory.newTransform(
//				CanonicalizationMethod.XPATH, new XPathFilterParameterSpec(
//						"not(ancestor-or-self::ds:Signature)",
//						xpathNamespaceMap));

        // XPath v2 - fast...
        List<XPathType> types = new ArrayList<XPathType>(1);
        types.add(new XPathType("/descendant::*[name()='ds:Signature']", XPathType.Filter.SUBTRACT, xpathNamespaceMap));
        Transform envelopedTransform = signatureFactory.newTransform(
                CanonicalizationMethod.XPATH2, new XPathFilter2ParameterSpec(types));

        transforms.add(envelopedTransform);

        Transform exclusiveTransform = signatureFactory
				.newTransform(CanonicalizationMethod.EXCLUSIVE,
						(TransformParameterSpec) null);
		transforms.add(exclusiveTransform);

		Reference reference = signatureFactory.newReference("", digestMethod,
				transforms, null, this.dsReferenceId);

		references.add(reference);
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}
}
