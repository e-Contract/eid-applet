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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLDecoder;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Attr;

/**
 * Apache XML Security resource resolver implementation using an ODF file as
 * resource repository.
 * 
 * @author fcorneli
 * 
 */
public class ODFResourceResolverSpi extends ResourceResolverSpi {

	private static final Log LOG = LogFactory
			.getLog(ODFResourceResolverSpi.class);

	private final URL odfUrl;

	public ODFResourceResolverSpi(URL odfUrl) {
		this.odfUrl = odfUrl;
	}

	@Override
	public boolean engineCanResolve(Attr uri, String baseUri) {
		String uriValue = uri.getValue();
		LOG.debug("engineCanResolve " + uriValue);
		InputStream dataInputStream;
		try {
			dataInputStream = findDataInputStream(uriValue);
		} catch (IOException e) {
			LOG.warn("IO error: " + e.getMessage(), e);
			return false;
		}
		if (null != dataInputStream) {
			return true;
		}
		return false;
	}

	@Override
	public XMLSignatureInput engineResolve(Attr uri, String baseUri)
			throws ResourceResolverException {
		String uriValue = uri.getValue();
		LOG.debug("engineResolve " + uriValue);
		InputStream dataInputStream;
		try {
			dataInputStream = findDataInputStream(uriValue);
			return new XMLSignatureInput(dataInputStream);
		} catch (IOException e) {
			LOG.warn("IO error: " + e.getMessage(), e);
		}
		return null;
	}

	private InputStream findDataInputStream(String uri) throws IOException {
		uri = URLDecoder.decode(uri, "UTF-8");
		InputStream odfInputStream = this.odfUrl.openStream();
		ZipInputStream odfZipInputStream = new ZipInputStream(odfInputStream);
		ZipEntry zipEntry;
		while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
			if (zipEntry.getName().equals(uri)) {
				return odfZipInputStream;
			}
		}
		return null;
	}
}