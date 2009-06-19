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

import java.io.OutputStream;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.URIDereferencer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Signature Service implementation for OpenDocument.
 * 
 * @author fcorneli
 * 
 */
abstract public class AbstractODFSignatureService extends
		AbstractXmlSignatureService {

	private static final Log LOG = LogFactory
			.getLog(AbstractODFSignatureService.class);

	public AbstractODFSignatureService() {
		super();
	}

	@Override
	protected final List<String> getReferenceUris() {
		List<String> referenceUris = new LinkedList<String>();
		referenceUris.add("content.xml");
		referenceUris.add("styles.xml");
		referenceUris.add("meta.xml");
		referenceUris.add("settings.xml");
		return referenceUris;
	}

	/**
	 * Gives back the URL of the ODF to be signed.
	 * 
	 * @return
	 */
	abstract protected URL getOpenDocumentURL();

	@Override
	protected final URIDereferencer getURIDereferencer() {
		URL odfUrl = getOpenDocumentURL();
		return new ODFURIDereferencer(odfUrl);
	}

	@Override
	protected String getSignatureDescription() {
		return "ODF Signature";
	}

	@Override
	protected OutputStream getSignedDocumentOutputStream() {
		return null;
	}

	public final String getFilesDigestAlgorithm() {
		/*
		 * No local files to digest.
		 */
		return null;
	}
}
