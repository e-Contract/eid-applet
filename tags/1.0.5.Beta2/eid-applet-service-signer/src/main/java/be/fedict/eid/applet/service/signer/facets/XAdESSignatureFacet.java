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
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
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
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.PrincipalUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.SignatureFacet;
import be.fedict.eid.applet.service.signer.jaxb.xades132.AnyType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.CertIDListType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.CertIDType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.ClaimedRolesListType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.DataObjectFormatType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.DigestAlgAndValueType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.IdentifierType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.ObjectFactory;
import be.fedict.eid.applet.service.signer.jaxb.xades132.ObjectIdentifierType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.QualifyingPropertiesType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SigPolicyQualifiersListType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignaturePolicyIdType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignaturePolicyIdentifierType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignedDataObjectPropertiesType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignedPropertiesType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignedSignaturePropertiesType;
import be.fedict.eid.applet.service.signer.jaxb.xades132.SignerRoleType;
import be.fedict.eid.applet.service.signer.jaxb.xmldsig.DigestMethodType;
import be.fedict.eid.applet.service.signer.jaxb.xmldsig.X509IssuerSerialType;
import be.fedict.eid.applet.service.signer.time.Clock;
import be.fedict.eid.applet.service.signer.time.LocalClock;

/**
 * XAdES Signature Facet. Implements XAdES v1.4.1 which is compatible with XAdES
 * v1.3.2. The implemented XAdES format is XAdES-BES/EPES. It's up to another
 * part of the signature service to upgrade the XAdES-BES to a XAdES-X-L.
 * 
 * This implementation has been tested against an implementation that
 * participated multiple ETSI XAdES plugtests.
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

	private final DigestAlgo digestAlgorithm;

	private final SignaturePolicyService signaturePolicyService;

	private String idSignedProperties;

	private boolean signaturePolicyImplied;

	private final XAdESNamespacePrefixMapper xadesNamespacePrefixMapper;

	private String role;

	private boolean issuerNameNoReverseOrder = false;

	private Map<String, String> dataObjectFormatMimeTypes;

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
		this(clock, DigestAlgo.SHA1);
	}

	/**
	 * Convenience constructor. Will use a local clock.
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used for all required XAdES digest
	 *            operations. Possible values: "SHA-1", "SHA-256", or "SHA-512".
	 */
	public XAdESSignatureFacet(DigestAlgo digestAlgorithm) {
		this(new LocalClock(), digestAlgorithm);
	}

	/**
	 * Convenience constructor. Will use a local clock.
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used for all required XAdES digest
	 *            operations. Possible values: "SHA-1", "SHA-256", or "SHA-512".
	 * @param signaturePolicyService
	 *            the optional signature policy service used for XAdES-EPES.
	 */
	public XAdESSignatureFacet(DigestAlgo digestAlgorithm,
			SignaturePolicyService signaturePolicyService) {
		this(new LocalClock(), digestAlgorithm, signaturePolicyService);
	}

	/**
	 * Convenience constructor. Will use a local clock and "SHA-1" as digest
	 * algorithm.
	 * 
	 * @param signaturePolicyService
	 *            the optional signature policy service used for XAdES-EPES.
	 */
	public XAdESSignatureFacet(SignaturePolicyService signaturePolicyService) {
		this(new LocalClock(), DigestAlgo.SHA1, signaturePolicyService);
	}

	/**
	 * Convenience constructor.
	 * 
	 * @param clock
	 *            the clock to be used for determining the xades:SigningTime
	 * @param digestAlgorithm
	 *            the digest algorithm to be used for all required XAdES digest
	 *            operations. Possible values: "SHA-1", "SHA-256", or "SHA-512".
	 */
	public XAdESSignatureFacet(Clock clock, DigestAlgo digestAlgorithm) {
		this(clock, digestAlgorithm, null);
	}

	/**
	 * Main constructor.
	 * 
	 * @param clock
	 *            the clock to be used for determining the xades:SigningTime
	 * @param digestAlgorithm
	 *            the digest algorithm to be used for all required XAdES digest
	 *            operations. Possible values: "SHA-1", "SHA-256", or "SHA-512".
	 * @param signaturePolicyService
	 *            the optional signature policy service used for XAdES-EPES.
	 */
	public XAdESSignatureFacet(Clock clock, DigestAlgo digestAlgorithm,
			SignaturePolicyService signaturePolicyService) {
		this.clock = clock;
		this.digestAlgorithm = digestAlgorithm;
		this.signaturePolicyService = signaturePolicyService;

		try {
			this.datatypeFactory = DatatypeFactory.newInstance();
		} catch (DatatypeConfigurationException e) {
			throw new RuntimeException("datatype config error: "
					+ e.getMessage(), e);
		}
		this.xadesObjectFactory = new ObjectFactory();
		this.xmldsigObjectFactory = new be.fedict.eid.applet.service.signer.jaxb.xmldsig.ObjectFactory();
		this.xadesNamespacePrefixMapper = new XAdESNamespacePrefixMapper();
		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(ObjectFactory.class);
			this.marshaller = jaxbContext.createMarshaller();
			this.marshaller.setProperty(
					"com.sun.xml.bind.namespacePrefixMapper",
					this.xadesNamespacePrefixMapper);
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}
		this.dataObjectFormatMimeTypes = new HashMap<String, String>();
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
		String signedPropertiesId;
		if (null != this.idSignedProperties) {
			signedPropertiesId = this.idSignedProperties;
		} else {
			signedPropertiesId = signatureId + "-xades";
		}
		signedProperties.setId(signedPropertiesId);
		qualifyingProperties.setSignedProperties(signedProperties);

		// SignedSignatureProperties
		SignedSignaturePropertiesType signedSignatureProperties = this.xadesObjectFactory
				.createSignedSignaturePropertiesType();
		signedProperties
				.setSignedSignatureProperties(signedSignatureProperties);

		// SigningTime
		GregorianCalendar signingTime = new GregorianCalendar(
				TimeZone.getTimeZone("Z"));
		Date currentClockValue = this.clock.getTime();
		signingTime.setTime(currentClockValue);
		XMLGregorianCalendar xmlGregorianCalendar = this.datatypeFactory
				.newXMLGregorianCalendar(signingTime);
		xmlGregorianCalendar.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
		signedSignatureProperties.setSigningTime(xmlGregorianCalendar);

		// SigningCertificate
		if (null == signingCertificateChain
				|| signingCertificateChain.isEmpty()) {
			throw new RuntimeException("no signing certificate chain available");
		}
		X509Certificate signingCertificate = signingCertificateChain.get(0);
		CertIDType signingCertificateId = getCertID(signingCertificate,
				this.xadesObjectFactory, this.xmldsigObjectFactory,
				this.digestAlgorithm, this.issuerNameNoReverseOrder);
		CertIDListType signingCertificates = this.xadesObjectFactory
				.createCertIDListType();
		signingCertificates.getCert().add(signingCertificateId);
		signedSignatureProperties.setSigningCertificate(signingCertificates);

		// ClaimedRole
		if (null != this.role && false == this.role.isEmpty()) {
			SignerRoleType signerRole = this.xadesObjectFactory
					.createSignerRoleType();
			signedSignatureProperties.setSignerRole(signerRole);
			ClaimedRolesListType claimedRolesList = this.xadesObjectFactory
					.createClaimedRolesListType();
			signerRole.setClaimedRoles(claimedRolesList);
			AnyType claimedRole = this.xadesObjectFactory.createAnyType();
			claimedRole.getContent().add(this.role);
			claimedRolesList.getClaimedRole().add(claimedRole);
		}

		// XAdES-EPES
		if (null != this.signaturePolicyService) {
			SignaturePolicyIdentifierType signaturePolicyIdentifier = this.xadesObjectFactory
					.createSignaturePolicyIdentifierType();
			signedSignatureProperties
					.setSignaturePolicyIdentifier(signaturePolicyIdentifier);

			SignaturePolicyIdType signaturePolicyId = this.xadesObjectFactory
					.createSignaturePolicyIdType();
			signaturePolicyIdentifier.setSignaturePolicyId(signaturePolicyId);

			ObjectIdentifierType objectIdentifier = this.xadesObjectFactory
					.createObjectIdentifierType();
			signaturePolicyId.setSigPolicyId(objectIdentifier);
			IdentifierType identifier = this.xadesObjectFactory
					.createIdentifierType();
			objectIdentifier.setIdentifier(identifier);
			identifier.setValue(this.signaturePolicyService
					.getSignaturePolicyIdentifier());
			objectIdentifier.setDescription(this.signaturePolicyService
					.getSignaturePolicyDescription());

			byte[] signaturePolicyDocumentData = this.signaturePolicyService
					.getSignaturePolicyDocument();
			DigestAlgAndValueType sigPolicyHash = getDigestAlgAndValue(
					signaturePolicyDocumentData, this.xadesObjectFactory,
					this.xmldsigObjectFactory, this.digestAlgorithm);
			signaturePolicyId.setSigPolicyHash(sigPolicyHash);

			String signaturePolicyDownloadUrl = this.signaturePolicyService
					.getSignaturePolicyDownloadUrl();
			if (null != signaturePolicyDownloadUrl) {
				SigPolicyQualifiersListType sigPolicyQualifiers = this.xadesObjectFactory
						.createSigPolicyQualifiersListType();
				signaturePolicyId.setSigPolicyQualifiers(sigPolicyQualifiers);

				AnyType sigPolicyQualifier = this.xadesObjectFactory
						.createAnyType();
				sigPolicyQualifiers.getSigPolicyQualifier().add(
						sigPolicyQualifier);

				JAXBElement<String> spUriElement = this.xadesObjectFactory
						.createSPURI(signaturePolicyDownloadUrl);
				sigPolicyQualifier.getContent().add(spUriElement);
			}
		} else if (this.signaturePolicyImplied) {
			SignaturePolicyIdentifierType signaturePolicyIdentifier = this.xadesObjectFactory
					.createSignaturePolicyIdentifierType();
			signedSignatureProperties
					.setSignaturePolicyIdentifier(signaturePolicyIdentifier);

			signaturePolicyIdentifier.setSignaturePolicyImplied("");
		}

		// DataObjectFormat
		if (false == this.dataObjectFormatMimeTypes.isEmpty()) {
			SignedDataObjectPropertiesType signedDataObjectProperties = this.xadesObjectFactory
					.createSignedDataObjectPropertiesType();
			signedProperties
					.setSignedDataObjectProperties(signedDataObjectProperties);

			List<DataObjectFormatType> dataObjectFormats = signedDataObjectProperties
					.getDataObjectFormat();
			for (Map.Entry<String, String> dataObjectFormatMimeType : this.dataObjectFormatMimeTypes
					.entrySet()) {
				DataObjectFormatType dataObjectFormat = this.xadesObjectFactory
						.createDataObjectFormatType();
				dataObjectFormat.setObjectReference("#"
						+ dataObjectFormatMimeType.getKey());
				dataObjectFormat.setMimeType(dataObjectFormatMimeType
						.getValue());
				dataObjectFormats.add(dataObjectFormat);
			}
		}

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
				digestAlgorithm.getXmlAlgoId(), null);
		List<Transform> transforms = new LinkedList<Transform>();
		Transform exclusiveTransform = signatureFactory
				.newTransform(CanonicalizationMethod.INCLUSIVE,
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

	/**
	 * Gives back the JAXB DigestAlgAndValue data structure.
	 * 
	 * @param data
	 * @param xadesObjectFactory
	 * @param xmldsigObjectFactory
	 * @param digestAlgorithm
	 * @return
	 */
	public static DigestAlgAndValueType getDigestAlgAndValue(
			byte[] data,
			ObjectFactory xadesObjectFactory,
			be.fedict.eid.applet.service.signer.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory,
			DigestAlgo digestAlgorithm) {
		DigestAlgAndValueType digestAlgAndValue = xadesObjectFactory
				.createDigestAlgAndValueType();

		DigestMethodType digestMethod = xmldsigObjectFactory
				.createDigestMethodType();
		digestAlgAndValue.setDigestMethod(digestMethod);
		digestMethod.setAlgorithm(digestAlgorithm.getXmlAlgoId());

		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(digestAlgorithm
					.getAlgoId());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("message digest algo error: "
					+ e.getMessage(), e);
		}
		byte[] digestValue = messageDigest.digest(data);
		digestAlgAndValue.setDigestValue(digestValue);

		return digestAlgAndValue;
	}

	/**
	 * Gives back the JAXB CertID data structure.
	 * 
	 * @param certificate
	 * @param xadesObjectFactory
	 * @param xmldsigObjectFactory
	 * @param digestAlgorithm
	 * @return
	 */
	public static CertIDType getCertID(
			X509Certificate certificate,
			ObjectFactory xadesObjectFactory,
			be.fedict.eid.applet.service.signer.jaxb.xmldsig.ObjectFactory xmldsigObjectFactory,
			DigestAlgo digestAlgorithm, boolean issuerNameNoReverseOrder) {
		CertIDType certId = xadesObjectFactory.createCertIDType();

		X509IssuerSerialType issuerSerial = xmldsigObjectFactory
				.createX509IssuerSerialType();
		certId.setIssuerSerial(issuerSerial);
		String issuerName;
		if (issuerNameNoReverseOrder) {
			try {
				/*
				 * Make sure the DN is encoded using the same order as present
				 * within the certificate. This is an Office2010 work-around.
				 * Should be reverted back.
				 * 
				 * XXX: not correct according to RFC 4514.
				 */
				issuerName = PrincipalUtil.getIssuerX509Principal(certificate)
						.getName().replace(",", ", ");
			} catch (CertificateEncodingException e) {
				throw new RuntimeException("cert encoding error: "
						+ e.getMessage(), e);
			}
		} else {
			issuerName = certificate.getIssuerX500Principal().toString();
		}
		issuerSerial.setX509IssuerName(issuerName);
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

	/**
	 * Adds a mime-type for the given ds:Reference (referred via its @URI). This
	 * information is added via the xades:DataObjectFormat element.
	 * 
	 * @param dsReferenceUri
	 * @param mimetype
	 */
	public void addMimeType(String dsReferenceUri, String mimetype) {
		this.dataObjectFormatMimeTypes.put(dsReferenceUri, mimetype);
	}

	/**
	 * Sets the Id that will be used on the SignedProperties element;
	 * 
	 * @param idSignedProperties
	 */
	public void setIdSignedProperties(String idSignedProperties) {
		this.idSignedProperties = idSignedProperties;
	}

	/**
	 * Sets the signature policy to implied.
	 * 
	 * @param signaturePolicyImplied
	 */
	public void setSignaturePolicyImplied(boolean signaturePolicyImplied) {
		this.signaturePolicyImplied = signaturePolicyImplied;
	}

	/**
	 * Sets the XAdES XML namespace prefix.
	 * 
	 * @param xadesNamespacePrefix
	 */
	public void setXadesNamespacePrefix(String xadesNamespacePrefix) {
		this.xadesNamespacePrefixMapper
				.setXAdESNamespacePrefix(xadesNamespacePrefix);
	}

	/**
	 * Sets the XAdES claimed role.
	 * 
	 * @param role
	 */
	public void setRole(String role) {
		this.role = role;
	}

	/**
	 * Work-around for Office 2010 IssuerName encoding.
	 * 
	 * @param reverseOrder
	 */
	public void setIssuerNameNoReverseOrder(boolean reverseOrder) {
		this.issuerNameNoReverseOrder = reverseOrder;
	}
}
