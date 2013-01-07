/*
 * eID Applet Project.
 * Copyright (C) 2009-2011 FedICT.
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

package be.fedict.eid.applet.service.signer.asic;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.fedict.eid.applet.service.signer.DigestAlgo;
import be.fedict.eid.applet.service.signer.SignatureFacet;

/**
 * Associated Signature Container signature facet implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class ASiCSignatureFacet implements SignatureFacet {

	private final File tmpZipFile;

	private final DigestAlgo digestAlgo;

	public ASiCSignatureFacet(File tmpZipFile, DigestAlgo digestAlgo) {
		this.tmpZipFile = tmpZipFile;
		this.digestAlgo = digestAlgo;
	}

	public void preSign(XMLSignatureFactory signatureFactory,
			Document document, String signatureId,
			List<X509Certificate> signingCertificateChain,
			List<Reference> references, List<XMLObject> objects)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		FileInputStream fileInputStream;
		try {
			fileInputStream = new FileInputStream(this.tmpZipFile);
		} catch (FileNotFoundException e) {
			throw new RuntimeException("tmp file not found: " + e.getMessage(),
					e);
		}

		DigestMethod digestMethod = signatureFactory.newDigestMethod(
				this.digestAlgo.getXmlAlgoId(), null);

		ZipInputStream zipInputStream = new ZipInputStream(fileInputStream);
		ZipEntry zipEntry;
		try {
			while (null != (zipEntry = zipInputStream.getNextEntry())) {
				if (ASiCUtil.isSignatureZipEntry(zipEntry)) {
					continue;
				}
				String uri = URLEncoder.encode(zipEntry.getName(), "UTF-8");
				Reference reference = signatureFactory.newReference(uri,
						digestMethod);
				references.add(reference);
			}
		} catch (IOException e) {
			throw new RuntimeException("I/O error: " + e.getMessage(), e);
		}
	}

	public void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		// empty
	}
}
