/*
 * eID Applet Project.
 * Copyright (C) 2010-2011 FedICT.
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.signer.odf.ODFUtil;

public class ASiCURIDereferencer implements URIDereferencer {

	private static final Log LOG = LogFactory.getLog(ASiCURIDereferencer.class);

	private final File tmpFile;

	private final byte[] data;

	private final URIDereferencer baseUriDereferener;

	public ASiCURIDereferencer(File tmpFile) {
		this(null, tmpFile);
	}

	public ASiCURIDereferencer(byte[] data) {
		this(data, null);
	}

	protected ASiCURIDereferencer(byte[] data, File tmpFile) {
		this.data = data;
		this.tmpFile = tmpFile;

		XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory
				.getInstance();
		this.baseUriDereferener = xmlSignatureFactory.getURIDereferencer();
	}

	public Data dereference(URIReference uriReference, XMLCryptoContext context)
			throws URIReferenceException {
		if (null == uriReference) {
			throw new URIReferenceException("URIReference cannot be null");
		}
		if (null == context) {
			throw new URIReferenceException("XMLCrytoContext cannot be null");
		}

		String uri = uriReference.getURI();
		try {
			uri = URLDecoder.decode(uri, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.warn("could not URL decode the uri: " + uri);
		}
		LOG.debug("dereference: " + uri);

		InputStream zipInputStream;
		if (null != this.tmpFile) {
			try {
				zipInputStream = new FileInputStream(this.tmpFile);
			} catch (FileNotFoundException e) {
				throw new URIReferenceException("file not found error: "
						+ e.getMessage(), e);
			}
		} else {
			zipInputStream = new ByteArrayInputStream(this.data);
		}
		InputStream dataInputStream;
		try {
			dataInputStream = ODFUtil.findDataInputStream(zipInputStream, uri);
		} catch (IOException e) {
			throw new URIReferenceException("I/O error: " + e.getMessage(), e);
		}
		if (null == dataInputStream) {
			return this.baseUriDereferener.dereference(uriReference, context);
		}
		return new OctetStreamData(dataInputStream, uri, null);
	}
}
