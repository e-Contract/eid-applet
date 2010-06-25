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

/*
 * Copyright (C) 2008-2009 FedICT.
 * This file is part of the eID Applet Project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package be.fedict.eid.applet.service.signer.facets;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jcp.xml.dsig.internal.dom.DOMKeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.fedict.eid.applet.service.signer.SignatureFacet;

/**
 * Signature Facet implementation that adds ds:KeyInfo to the XML signature.
 * 
 * @author fcorneli
 * 
 */
public class KeyInfoSignatureFacet implements SignatureFacet {

	private static final Log LOG = LogFactory
			.getLog(KeyInfoSignatureFacet.class);

	private final boolean includeEntireCertificateChain;

	private final boolean includeIssuerSerial;

	private final boolean includeKeyValue;

	/**
	 * Main constructor.
	 * 
	 * @param includeEntireCertificateChain
	 * @param includeIssuerSerial
	 * @param includeKeyValue
	 */
	public KeyInfoSignatureFacet(boolean includeEntireCertificateChain,
			boolean includeIssuerSerial, boolean includeKeyValue) {
		this.includeEntireCertificateChain = includeEntireCertificateChain;
		this.includeIssuerSerial = includeIssuerSerial;
		this.includeKeyValue = includeKeyValue;
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");
		/*
		 * Make sure we insert right after the ds:SignatureValue element, just
		 * before the first ds:Object element.
		 */
		Node nextSibling;
		NodeList objectNodeList = signatureElement.getElementsByTagNameNS(
				"http://www.w3.org/2000/09/xmldsig#", "Object");
		if (0 == objectNodeList.getLength()) {
			nextSibling = null;
		} else {
			nextSibling = objectNodeList.item(0);
		}

		/*
		 * Construct the ds:KeyInfo element using JSR 105.
		 */
		KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance();
		List<Object> x509DataObjects = new LinkedList<Object>();
		X509Certificate signingCertificate = signingCertificateChain.get(0);

		List<Object> keyInfoContent = new LinkedList<Object>();

		if (this.includeKeyValue) {
			KeyValue keyValue;
			try {
				keyValue = keyInfoFactory.newKeyValue(signingCertificate
						.getPublicKey());
			} catch (KeyException e) {
				throw new RuntimeException("key exception: " + e.getMessage(),
						e);
			}
			keyInfoContent.add(keyValue);
		}

		if (this.includeIssuerSerial) {
			x509DataObjects.add(keyInfoFactory.newX509IssuerSerial(
					signingCertificate.getIssuerX500Principal().toString(),
					signingCertificate.getSerialNumber()));
		}

		if (this.includeEntireCertificateChain) {
			for (X509Certificate certificate : signingCertificateChain) {
				x509DataObjects.add(certificate);
			}
		} else {
			x509DataObjects.add(signingCertificate);
		}

		if (false == x509DataObjects.isEmpty()) {
			X509Data x509Data = keyInfoFactory.newX509Data(x509DataObjects);
			keyInfoContent.add(x509Data);
		}
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(keyInfoContent);
		DOMKeyInfo domKeyInfo = (DOMKeyInfo) keyInfo;

		Key key = new Key() {
			private static final long serialVersionUID = 1L;

			public String getAlgorithm() {
				return null;
			}

			public byte[] getEncoded() {
				return null;
			}

			public String getFormat() {
				return null;
			}
		};

		XMLSignContext xmlSignContext = new DOMSignContext(key,
				signatureElement);
		DOMCryptoContext domCryptoContext = (DOMCryptoContext) xmlSignContext;
		String dsPrefix = null;
		try {
			domKeyInfo.marshal(signatureElement, nextSibling, dsPrefix,
					domCryptoContext);
		} catch (MarshalException e) {
			throw new RuntimeException("marshall error: " + e.getMessage(), e);
		}
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		// empty
	}
}
