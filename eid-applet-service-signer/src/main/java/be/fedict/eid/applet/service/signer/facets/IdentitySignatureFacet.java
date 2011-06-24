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
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.jaxb.identity.GenderType;
import be.fedict.eid.applet.service.signer.jaxb.identity.IdentityType;
import be.fedict.eid.applet.service.signer.jaxb.identity.ObjectFactory;
import be.fedict.eid.applet.service.signer.jaxb.identity.PhotoType;
import be.fedict.eid.applet.service.spi.IdentityDTO;

/**
 * Signature Facet implementation doing an eID identity ds:Object.
 * 
 * @author Frank Cornelis
 * 
 */
public class IdentitySignatureFacet implements SignatureFacet {

	public static final String REFERENCE_TYPE = "be:fedict:eid:identity:1.0";
	public static final String NAMESPACE_URI = "be:fedict:eid:identity:1.0";

	private final IdentityDTO identityDTO;
	private final byte[] photoData;
	private final ObjectFactory objectFactory;
	private final Marshaller marshaller;
	private final DigestAlgo digestAlgo;

	public IdentitySignatureFacet(IdentityDTO identity, byte[] photo,
			DigestAlgo digestAlgo) {
		this.identityDTO = identity;
		this.photoData = photo;
        this.digestAlgo = digestAlgo;
		this.objectFactory = new ObjectFactory();

		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(ObjectFactory.class);
			this.marshaller = jaxbContext.createMarshaller();
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// construct identity document
		IdentityType identity = this.objectFactory.createIdentityType();
		String identityId = "identity-" + UUID.randomUUID().toString();
		identity.setId(identityId);
		if (null != this.identityDTO) {
			identity.setFirstName(this.identityDTO.firstName);
			identity.setName(this.identityDTO.name);
			identity.setMiddleName(this.identityDTO.middleName);
			GenderType gender;
			if (this.identityDTO.male) {
				gender = GenderType.MALE;
			} else {
				gender = GenderType.FEMALE;
			}
			identity.setGender(gender);
		}
		if (null != this.photoData) {
			PhotoType photo = this.objectFactory.createPhotoType();
			photo.setValue(this.photoData);
			photo.setMimeType("image/jpeg");
			identity.setPhoto(photo);
		}

		// marshalling
		Node marshallNode = document.createElement("marshall-node");
		try {
			this.marshaller.marshal(
					this.objectFactory.createIdentity(identity), marshallNode);
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
		Node identityNode = marshallNode.getFirstChild();

		// ds:Object
		String objectId = "identity-object-" + UUID.randomUUID().toString();

		List<XMLStructure> identityObjectContent = new LinkedList<XMLStructure>();
		identityObjectContent.add(new DOMStructure(identityNode));
		XMLObject identityObject = signatureFactory.newXMLObject(
				identityObjectContent, objectId, null, null);
		objects.add(identityObject);

		// ds:Reference
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				this.digestAlgo.getXmlAlgoId(), null);
		List<Transform> transforms = new LinkedList<Transform>();
		Transform exclusiveTransform = signatureFactory
				.newTransform(CanonicalizationMethod.INCLUSIVE,
						(TransformParameterSpec) null);
		transforms.add(exclusiveTransform);
		Reference reference = signatureFactory.newReference("#" + objectId,
				digestMethod, transforms, REFERENCE_TYPE, null);
		references.add(reference);
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}
}
