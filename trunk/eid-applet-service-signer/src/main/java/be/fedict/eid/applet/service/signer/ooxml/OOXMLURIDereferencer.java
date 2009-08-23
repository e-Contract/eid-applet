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

package be.fedict.eid.applet.service.signer.ooxml;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * JSR105 URI dereferencer for Office Open XML documents.
 * 
 * @author Frank Cornelis
 * 
 */
public class OOXMLURIDereferencer implements URIDereferencer {

	private static final Log LOG = LogFactory
			.getLog(OOXMLURIDereferencer.class);

	private final URL ooxmlUrl;

	private final URIDereferencer baseUriDereferencer;

	public OOXMLURIDereferencer(URL ooxmlUrl) {
		if (null == ooxmlUrl) {
			throw new IllegalArgumentException("ooxmlUrl is null");
		}
		this.ooxmlUrl = ooxmlUrl;
		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		this.baseUriDereferencer = xmlSignatureFactory.getURIDereferencer();
	}

	public Data dereference(URIReference uriReference, XMLCryptoContext context)
			throws URIReferenceException {
		if (null == uriReference) {
			throw new NullPointerException("URIReference cannot be null");
		}
		if (null == context) {
			throw new NullPointerException("XMLCrytoContext cannot be null");
		}

		String uri = uriReference.getURI();
		try {
			uri = URLDecoder.decode(uri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.warn("could not URL decode the uri: " + uri);
		}
		LOG.debug("dereference: " + uri);
		try {
			InputStream dataInputStream = findDataInputStream(uri);
			if (null == dataInputStream) {
				LOG
						.debug("cannot resolve, delegating to base DOM URI dereferencer: "
								+ uri);
				return this.baseUriDereferencer.dereference(uriReference,
						context);
			}
			return new OctetStreamData(dataInputStream, uri, null);
		} catch (IOException e) {
			throw new URIReferenceException("I/O error: " + e.getMessage(), e);
		}
	}

	private InputStream findDataInputStream(String uri) throws IOException {
		String entryName;
		if (uri.startsWith("/")) {
			entryName = uri.substring(1); // remove '/'
			entryName = entryName.substring(0, entryName.indexOf("?"));
			LOG.debug("ZIP entry name: " + entryName);
		} else {
			entryName = uri.toString();
		}
		InputStream odfInputStream = this.ooxmlUrl.openStream();
		ZipInputStream odfZipInputStream = new ZipInputStream(odfInputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
			if (zipEntry.getName().equals(entryName)) {
				return odfZipInputStream;
			}
		}
		return null;
	}
}
