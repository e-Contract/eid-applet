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

package be.fedict.eid.applet.service.signer;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * JSR105 key selector implementation using the ds:KeyInfo data of the signature
 * itself.
 * 
 * @author fcorneli
 * 
 */
public class KeyInfoKeySelector extends KeySelector implements
		KeySelectorResult {

	private static final Log LOG = LogFactory.getLog(KeyInfoKeySelector.class);

	private X509Certificate certificate;

	@Override
	public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
			AlgorithmMethod method, XMLCryptoContext context)
			throws KeySelectorException {
		LOG.debug("select key");
		List<XMLStructure> keyInfoContent = keyInfo.getContent();
		this.certificate = null;
		for (XMLStructure keyInfoStructure : keyInfoContent) {
			if (false == (keyInfoStructure instanceof X509Data)) {
				continue;
			}
			X509Data x509Data = (X509Data) keyInfoStructure;
			List<Object> x509DataList = x509Data.getContent();
			for (Object x509DataObject : x509DataList) {
				if (false == (x509DataObject instanceof X509Certificate)) {
					continue;
				}
				X509Certificate certificate = (X509Certificate) x509DataObject;
				LOG.debug("certificate: "
						+ certificate.getSubjectX500Principal());
				if (null == this.certificate) {
					/*
					 * The first certificate is presumably the signer.
					 */
					this.certificate = certificate;
				}
			}
			if (null != this.certificate) {
				return this;
			}
		}
		throw new KeySelectorException("No key found!");
	}

	public Key getKey() {
		return this.certificate.getPublicKey();
	}

	/**
	 * Gives back the X509 certificate used during the last signature
	 * verification operation.
	 * 
	 * @return
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}
}
