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

package be.fedict.eid.applet.service.signer.facets;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.jaxb.xades132.CertIDListType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.CertIDType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.DigestAlgAndValueType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.ObjectFactory;
import be.fedict.eid.applet.service.signer.jaxb.xades132.QualifyingPropertiesType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignedPropertiesType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignedSignaturePropertiesType;
import be.fedict.eid.applet.service.signer.jaxb.xmldsig.DigestMethodType;
import be.fedict.eid.applet.service.signer.jaxb.xmldsig.X509IssuerSerialType;

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

	private final be.fedict.eid.applet.service.signer.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory;

	private final Marshaller marshaller;

	private final Clock clock;

	private final String digestAlgorithm;

	private final String xmlDigestAlgorithm;

	/**
	 * Default constructor. Will use a local clock and "SHA-1" for digest
	 * algorithm.
	 */
	public XAdESSignatureFacet() {
		this(new LocalClock());
	}

	/**
	 * Convenience constructor. Will use "SHA-1" for digest algorithm.
	 * 
	 * @param clock
	 *            the clock to be used for determining the xades:SigningTime
	 */
	public XAdESSignatureFacet(Clock clock) {
		this(clock, "SHA-1");
	}

	/**
	 * Convenience constructor. Will use a local clock.
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used for all required XAdES digest
	 *            operations. Possible values: "SHA-1", "SHA-256", or "SHA-512".
	 */
	public XAdESSignatureFacet(String digestAlgorithm) {
		this(new LocalClock(), digestAlgorithm);
	}

	/**
	 * Main constructor.
	 * 
	 * @param clock
	 *            the clock to be used for determining the xades:SigningTime
	 * @param digestAlgorithm
	 *            the digest algorithm to be used for all required XAdES digest
	 *            operations. Possible values: "SHA-1", "SHA-256", or "SHA-512".
	 */
	public XAdESSignatureFacet(Clock clock, String digestAlgorithm) {
		this.clock = clock;
		this.digestAlgorithm = digestAlgorithm;
		this.xmlDigestAlgorithm = getXmlDigestAlgo(this.digestAlgorithm);

		try {
			this.datatypeFactory = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new RuntimeException("datatype config error: "
					+ e.getMessage(), e);
		}
		this.xadesObjectFactory = new ObjectFactory();
		this.xmldsigObjectFactory = new be.fedict.eid.applet.service.signer.jaxb.xmldsig.ObjectFactory();
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
		GregorianCalendar signingTime = new GregorianCalendar(TimeZone
				.getTimeZone("Z"));
		Date currentClockValue = this.clock.getTime();
		signingTime.setTime(currentClockValue);
		signedSignatureProperties.setSigningTime(this.datatypeFactory
				.newXMLGregorianCalendar(signingTime));

		// SigningCertificate
		if (null == signingCertificateChain
				|| signingCertificateChain.isEmpty()) {
			throw new RuntimeException("no signing certificate chain available");
		}
		X509Certificate signingCertificate = signingCertificateChain.get(0);
		CertIDType signingCertificateId = getCertID(signingCertificate,
				this.xadesObjectFactory, this.xmldsigObjectFactory,
				this.digestAlgorithm);
		CertIDListType signingCertificates = this.xadesObjectFactory
				.createCertIDListType();
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
				this.xmlDigestAlgorithm, null);
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

	private static String getXmlDigestAlgo(String digestAlgo) {
		if ("SHA-1".equals(digestAlgo)) {
			return DigestMethod.SHA1;
		}
		if ("SHA-256".equals(digestAlgo)) {
			return DigestMethod.SHA256;
		}
		if ("SHA-512".equals(digestAlgo)) {
			return DigestMethod.SHA512;
		}
		throw new RuntimeException("unsupported digest algo: " + digestAlgo);
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

	public static DigestAlgAndValueType getDigestAlgAndValue(
			byte[] data,
			ObjectFactory xadesObjectFactory,
			be.fedict.eid.applet.service.signer.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory,
			String digestAlgorithm) {
		DigestAlgAndValueType digestAlgAndValue = xadesObjectFactory
				.createDigestAlgAndValueType();

		DigestMethodType digestMethod = xmldsigObjectFactory
				.createDigestMethodType();
		digestAlgAndValue.setDigestMethod(digestMethod);
		String xmlDigestAlgorithm = getXmlDigestAlgo(digestAlgorithm);
		digestMethod.setAlgorithm(xmlDigestAlgorithm);

		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(digestAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("message digest algo error: "
					+ e.getMessage(), e);
		}
		byte[] digestValue = messageDigest.digest(data);
		digestAlgAndValue.setDigestValue(digestValue);

		return digestAlgAndValue;
	}

	public static CertIDType getCertID(
			X509Certificate certificate,
			ObjectFactory xadesObjectFactory,
			be.fedict.eid.applet.service.signer.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory,
			String digestAlgorithm) {
		CertIDType certId = xadesObjectFactory.createCertIDType();

		X509IssuerSerialType issuerSerial = xmldsigObjectFactory
				.createX509IssuerSerialType();
		certId.setIssuerSerial(issuerSerial);
		issuerSerial.setX509IssuerName(certificate.getIssuerX500Principal()
				.toString());
		issuerSerial.setX509SerialNumber(certificate.getSerialNumber());

		byte[] encodedCertificate;
		try {
			encodedCertificate = certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("certificate encoding error: "
					+ e.getMessage(), e);
		}
		DigestAlgAndValueType certDigest = getDigestAlgAndValue(
				encodedCertificate, xadesObjectFactory, xmldsigObjectFactory,
				digestAlgorithm);
		certId.setCertDigest(certDigest);

		return certId;
	}
}
