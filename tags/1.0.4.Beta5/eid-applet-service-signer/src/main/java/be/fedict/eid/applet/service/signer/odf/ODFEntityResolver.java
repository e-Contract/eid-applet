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

package be.fedict.eid.applet.service.signer.odf;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * ODF Entity Resolver for MathML DTD.
 * 
 * @author Frank Cornelis
 * 
 */
public class ODFEntityResolver implements EntityResolver {

	private static final Log LOG = LogFactory.getLog(ODFEntityResolver.class);

	public InputSource resolveEntity(String publicId, String systemId)
			throws SAXException, IOException {
		LOG.debug("resolveEntity");
		LOG.debug("publicId: " + publicId);
		LOG.debug("systemId: " + systemId);
		if ("-//OpenOffice.org//DTD Modified W3C MathML 1.01//EN"
				.equals(publicId)) {
			InputStream mathmlDtdInputStream = ODFEntityResolver.class
					.getResourceAsStream("/mmlents/mathml.dtd");
			InputSource inputSource = new InputSource(mathmlDtdInputStream);
			return inputSource;
		}
		if (systemId.endsWith(".ent")) {
			String filename = FilenameUtils.getBaseName(systemId);
			LOG.debug("ent filename: " + filename);
			InputStream entInputStream = ODFEntityResolver.class
					.getResourceAsStream("/mmlents/" + filename + ".ent");
			InputSource inputSource = new InputSource(entInputStream);
			return inputSource;
		}
		LOG.warn("could not resolve: " + publicId);
		return null;
	}
}
