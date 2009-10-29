/*
 * eID Digital Signature Service Project.
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

package be.fedict.eid.applet.service.signer.facets;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;

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
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.etsi.uri._01903.v1_3.CertIDListType;
import org.etsi.uri._01903.v1_3.CertIDType;
import org.etsi.uri._01903.v1_3.DigestAlgAndValueType;
import org.etsi.uri._01903.v1_3.ObjectFactory;
import org.etsi.uri._01903.v1_3.QualifyingPropertiesType;
import org.etsi.uri._01903.v1_3.SignedPropertiesType;
import org.etsi.uri._01903.v1_3.SignedSignaturePropertiesType;
import org.w3._2000._09.xmldsig_.DigestMethodType;
import org.w3._2000._09.xmldsig_.X509IssuerSerialType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.fedict.eid.applet.service.signer.SignatureFacet;

/**
 * XAdES Signature Facet. Implements XAdES v1.4.1 which is compatible with XAdES
 * v1.3.2. The implemented XAdES format is XAdES-BES. It's up to another part of
 * the signature service to upgrade the XAdES-BES to a XAdES-X-L.
 * 
 * @author Frank Cornelis
 * @see http://en.wikipedia.org/wiki/XAdES
 * 
 */
public class XAdESSignatureFacet implements SignatureFacet {

	private static final Log LOG = LogFactory.getLog(XAdESSignatureFacet.class);

	private static final String XADES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

	private final DatatypeFactory datatypeFactory;

	private final ObjectFactory xadesObjectFactory;

	private final org.w3._2000._09.xmldsig_.ObjectFactory xmldsigObjectFactory;

	private final Marshaller marshaller;

	public XAdESSignatureFacet() {
		try {
			this.datatypeFactory = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new RuntimeException("datatype config error: "
					+ e.getMessage(), e);
		}
		this.xadesObjectFactory = new ObjectFactory();
		this.xmldsigObjectFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(ObjectFactory.class);
			this.marshaller = jaxbContext.createMarshaller();
			this.marshaller.setProperty(
					"com.sun.xml.bind.namespacePrefixMapper",
					new XAdESNamespacePrefixMapper());
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		LOG.debug("preSign");

		// QualifyingProperties
		QualifyingPropertiesType qualifyingProperties = this.xadesObjectFactory
				.createQualifyingPropertiesType();
		qualifyingProperties.setTarget("#" + signatureId);

		// SignedProperties
		SignedPropertiesType signedProperties = this.xadesObjectFactory
				.createSignedPropertiesType();
		String signedPropertiesId = signatureId + "-xades";
		signedProperties.setId(signedPropertiesId);
		qualifyingProperties.setSignedProperties(signedProperties);

		// SignedSignatureProperties
		SignedSignaturePropertiesType signedSignatureProperties = this.xadesObjectFactory
				.createSignedSignaturePropertiesType();
		signedProperties
				.setSignedSignatureProperties(signedSignatureProperties);

		// SigningTime
		GregorianCalendar signingTime = new GregorianCalendar();
		signingTime.setTimeZone(TimeZone.getTimeZone("Z"));
		signedSignatureProperties.setSigningTime(this.datatypeFactory
				.newXMLGregorianCalendar(signingTime));

		// SigningCertificate
		CertIDListType signingCertificates = this.xadesObjectFactory
				.createCertIDListType();
		CertIDType signingCertificateId = this.xadesObjectFactory
				.createCertIDType();

		X509IssuerSerialType issuerSerial = this.xmldsigObjectFactory
				.createX509IssuerSerialType();
		if (null == signingCertificateChain
				|| signingCertificateChain.isEmpty()) {
			throw new RuntimeException("no signing certificate chain available");
		}
		X509Certificate signingCertificate = signingCertificateChain.get(0);
		issuerSerial.setX509IssuerName(signingCertificate
				.getIssuerX500Principal().toString());
		issuerSerial.setX509SerialNumber(signingCertificate.getSerialNumber());
		signingCertificateId.setIssuerSerial(issuerSerial);

		DigestAlgAndValueType certDigest = this.xadesObjectFactory
				.createDigestAlgAndValueType();
		DigestMethodType jaxbDigestMethod = xmldsigObjectFactory
				.createDigestMethodType();
		jaxbDigestMethod.setAlgorithm(DigestMethod.SHA1);
		certDigest.setDigestMethod(jaxbDigestMethod);
		MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
		byte[] digestValue;
		try {
			digestValue = messageDigest.digest(signingCertificate.getEncoded());
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("certificate encoding error: "
					+ e.getMessage(), e);
		}
		certDigest.setDigestValue(digestValue);
		signingCertificateId.setCertDigest(certDigest);

		signingCertificates.getCert().add(signingCertificateId);
		signedSignatureProperties.setSigningCertificate(signingCertificates);

		// marshall XAdES QualifyingProperties
		Node qualifyingPropertiesNode = marshallQualifyingProperties(document,
				this.xadesObjectFactory, qualifyingProperties);

		// add XAdES ds:Object
		List<XMLStructure> xadesObjectContent = new LinkedList<XMLStructure>();
		xadesObjectContent.add(new DOMStructure(qualifyingPropertiesNode));
		XMLObject xadesObject = signatureFactory.newXMLObject(
				xadesObjectContent, null, null, null);
		objects.add(xadesObject);

		// add XAdES ds:Reference
		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				DigestMethod.SHA1, null);
		List<Transform> transforms = new LinkedList<Transform>();
		Transform exclusiveTransform = signatureFactory
				.newTransform(CanonicalizationMethod.EXCLUSIVE,
						(TransformParameterSpec) null);
		transforms.add(exclusiveTransform);
		Reference reference = signatureFactory.newReference("#"
				+ signedPropertiesId, digestMethod, transforms, XADES_TYPE,
				null);
		references.add(reference);
	}

	private Node marshallQualifyingProperties(Document document,
			ObjectFactory xadesObjectFactory,
			QualifyingPropertiesType qualifyingProperties) {
		Node marshallNode = document.createElement("marshall-node");
		try {
			this.marshaller.marshal(xadesObjectFactory
					.createQualifyingProperties(qualifyingProperties),
					marshallNode);
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
		Node qualifyingPropertiesNode = marshallNode.getFirstChild();
		return qualifyingPropertiesNode;
	}
}
