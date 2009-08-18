/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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

package be.fedict.eid.applet.service.signer;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * ODF Signature Verifier.
 * 
 * @author fcorneli
 * 
 */
public class ODFSignatureVerifier {

	private static final Log LOG = LogFactory
			.getLog(ODFSignatureVerifier.class);

	private ODFSignatureVerifier() {
		super();
	}

	public static boolean hasOdfSignature(URL odfUrl) throws IOException,
			ParserConfigurationException, SAXException,
			org.apache.xml.security.signature.XMLSignatureException,
			XMLSecurityException, MarshalException, XMLSignatureException {
		List<X509Certificate> signers = getSigners(odfUrl);
		return false == signers.isEmpty();
	}

	public static List<X509Certificate> getSigners(URL odfUrl)
			throws IOException, ParserConfigurationException, SAXException,
			MarshalException, XMLSignatureException {
		List<X509Certificate> signers = new LinkedList<X509Certificate>();
		if (null == odfUrl) {
			throw new IllegalArgumentException("odfUrl is null");
		}
		ZipInputStream odfZipInputStream = new ZipInputStream(odfUrl
				.openStream());
		ZipEntry zipEntry;
		while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
			LOG.debug(zipEntry.getName());
			if (true == "META-INF/documentsignatures.xml".equals(zipEntry
					.getName())) {
				Document documentSignatures = loadDocument(odfZipInputStream);
				NodeList signatureNodeList = documentSignatures
						.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
				for (int idx = 0; idx < signatureNodeList.getLength(); idx++) {
					Node signatureNode = signatureNodeList.item(idx);
					X509Certificate signer = getVerifiedSignatureSigner(odfUrl,
							signatureNode);
					if (null == signer) {
						LOG.debug("JSR105 says invalid signature");
						continue;
					}
					signers.add(signer);
				}
				return signers;
			}
		}
		LOG.debug("no documentsignatures.xml entry present");
		return signers;
	}

	private static X509Certificate getVerifiedSignatureSigner(URL odfUrl,
			Node signatureNode) throws MarshalException, XMLSignatureException {
		if (null == odfUrl) {
			throw new IllegalArgumentException("odfUrl is null");
		}
		KeyInfoKeySelector keySelector = new KeyInfoKeySelector();
		DOMValidateContext domValidateContext = new DOMValidateContext(
				keySelector, signatureNode);
		ODFURIDereferencer dereferencer = new ODFURIDereferencer(odfUrl);
		domValidateContext.setURIDereferencer(dereferencer);
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		LOG.debug("java version: " + System.getProperty("java.version"));
		/*
		 * Requires Java 6u10 because of a bug. See also:
		 * http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6696582
		 */
		XMLSignature xmlSignature = xmlSignatureFactory
				.unmarshalXMLSignature(domValidateContext);
		boolean validity = xmlSignature.validate(domValidateContext);
		if (false == validity) {
			LOG.debug("invalid signature");
			return null;
		}
		X509Certificate signer = keySelector.getCertificate();
		if (null == signer) {
			throw new IllegalStateException("signer X509 certificate is null");
		}
		LOG.debug("signer: " + signer.getSubjectX500Principal());
		return signer;
	}

	private static Document loadDocument(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		InputSource inputSource = new InputSource(documentInputStream);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(inputSource);
		return document;
	}
}
