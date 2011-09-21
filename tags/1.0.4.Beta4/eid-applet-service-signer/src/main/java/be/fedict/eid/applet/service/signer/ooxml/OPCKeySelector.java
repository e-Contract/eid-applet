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

package be.fedict.eid.applet.service.signer.ooxml;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.signer.KeyInfoKeySelector;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationship;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.CTRelationships;
import be.fedict.eid.applet.service.signer.jaxb.opc.relationships.ObjectFactory;

/**
 * Open Packaging Conventions (ECMA-376-2) based JSR105 key selector
 * implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class OPCKeySelector extends KeyInfoKeySelector {

	private static final Log LOG = LogFactory.getLog(OPCKeySelector.class);

	private static final String DIGITAL_SIGNATURE_CERTIFICATE_REL_TYPE = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/certificate";

	private final String signatureResourceName;

	private final URL opcUrl;

	private final Unmarshaller relationshipsUnmarshaller;

	private final CertificateFactory certificateFactory;

	public OPCKeySelector(URL opcUrl, String signatureResourceName) {
		this.opcUrl = opcUrl;
		this.signatureResourceName = signatureResourceName;

		try {
			JAXBContext relationshipsJAXBContext = JAXBContext
					.newInstance(ObjectFactory.class);
			this.relationshipsUnmarshaller = relationshipsJAXBContext
					.createUnmarshaller();
		} catch (JAXBException e) {
			throw new RuntimeException("JAXB error: " + e.getMessage(), e);
		}

		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException("CertificateFactory error: "
					+ e.getMessage(), e);
		}
	}

	@Override
	public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
			AlgorithmMethod method, XMLCryptoContext context)
			throws KeySelectorException {
		try {
			return super.select(keyInfo, purpose, method, context);
		} catch (KeySelectorException e) {
			LOG.debug("no key found via ds:KeyInfo key selector");
		}
		LOG.debug("signature resource name: " + this.signatureResourceName);
		String signatureSegment = this.signatureResourceName.substring(0,
				this.signatureResourceName.lastIndexOf("/"));
		LOG.debug("signature segment: " + signatureSegment);
		String signatureBase = this.signatureResourceName
				.substring(this.signatureResourceName.lastIndexOf("/") + 1);
		LOG.debug("signature base: " + signatureBase);
		String signatureRelationshipResourceName = signatureSegment + "/_rels/"
				+ signatureBase + ".rels";
		LOG.debug("signature relationship resource name: "
				+ signatureRelationshipResourceName);

		ZipArchiveInputStream zipInputStream;
		try {
			zipInputStream = new ZipArchiveInputStream(
					this.opcUrl.openStream(), "UTF8", true, true);
		} catch (IOException e) {
			throw new KeySelectorException(e);
		}
		ZipArchiveEntry zipEntry;
		try {
			while (null != (zipEntry = zipInputStream.getNextZipEntry())) {
				if (signatureRelationshipResourceName
						.equals(zipEntry.getName())) {
					break;
				}
			}
		} catch (IOException e) {
			throw new KeySelectorException(e);
		}
		if (null == zipEntry) {
			LOG.warn("relationship part not present: "
					+ signatureRelationshipResourceName);
			throw new KeySelectorException("no key found");
		}
		LOG.debug("signature relationship part found");

		JAXBElement<CTRelationships> signatureRelationshipsElement;
		try {
			signatureRelationshipsElement = (JAXBElement<CTRelationships>) this.relationshipsUnmarshaller
					.unmarshal(zipInputStream);
		} catch (JAXBException e) {
			throw new KeySelectorException(e);
		}
		CTRelationships signatureRelationships = signatureRelationshipsElement
				.getValue();
		List<CTRelationship> signatureRelationshipList = signatureRelationships
				.getRelationship();
		List<String> certificateResourceNames = new LinkedList<String>();
		for (CTRelationship signatureRelationship : signatureRelationshipList) {
			if (DIGITAL_SIGNATURE_CERTIFICATE_REL_TYPE
					.equals(signatureRelationship.getType())) {
				String certificateResourceName = signatureRelationship
						.getTarget().substring(1);
				certificateResourceNames.add(certificateResourceName);
			}
		}

		X509Certificate endEntityCertificate = null;

		for (String certificateResourceName : certificateResourceNames) {
			try {
				zipInputStream = new ZipArchiveInputStream(
						this.opcUrl.openStream(), "UTF8", true, true);
			} catch (IOException e) {
				throw new KeySelectorException(e);
			}
			try {
				while (null != (zipEntry = zipInputStream.getNextZipEntry())) {
					if (certificateResourceName.equals(zipEntry.getName())) {
						break;
					}
				}
			} catch (IOException e) {
				throw new KeySelectorException(e);
			}
			if (null == zipEntry) {
				LOG.warn("certificate part not present: "
						+ certificateResourceName);
				continue;
			}
			X509Certificate certificate;
			try {
				certificate = (X509Certificate) this.certificateFactory
						.generateCertificate(zipInputStream);
			} catch (CertificateException e) {
				throw new KeySelectorException(e);
			}
			LOG.debug("certificate subject: "
					+ certificate.getSubjectX500Principal());
			if (-1 != certificate.getBasicConstraints()) {
				LOG.debug("skipping CA certificate");
				continue;
			}
			if (null != endEntityCertificate) {
				throw new KeySelectorException(
						"two possible end entity certificates");
			}
			endEntityCertificate = certificate;
		}
		if (null == endEntityCertificate) {
			throw new KeySelectorException("no key found");
		}
		this.certificate = endEntityCertificate;
		return this;
	}
}
