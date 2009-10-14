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
package be.fedict.eid.applet.service.signer.odf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.AbstractXmlSignatureService;
import be.fedict.eid.applet.service.signer.KeyInfoSignatureFacet;

/**
 * Signature Service implementation for OpenDocument format signatures.
 * 
 * The signatures created with this class are accepted as valid signature within
 * OpenOffice.org 3.x. They probably don't get accepted by older OOo versions.
 * 
 * @see http://wiki.services.openoffice.org/wiki/Security/Digital_Signatures
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
		addSignatureFacet(new OpenOfficeSignatureFacet());
		addSignatureFacet(new KeyInfoSignatureFacet(false, true, false));
	}

	@Override
	protected List<ReferenceInfo> getReferences() {
		List<ReferenceInfo> referenceInfos = new LinkedList<ReferenceInfo>();
		URL odfUrl = this.getOpenDocumentURL();
		try {
			InputStream odfInputStream = odfUrl.openStream();
			ZipInputStream odfZipInputStream = new ZipInputStream(
					odfInputStream);
			ZipEntry zipEntry;

			while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
				if (ODFUtil.isToBeSigned(zipEntry)) {
					String name = zipEntry.getName();
					/*
					 * Whitespaces are illegal in URIs
					 * 
					 * Note that OOo 3.0/3.1 seems to have a bug, seems like the
					 * OOo signature verification doesn't convert it back to
					 * whitespace, to be investigated
					 */
					String uri = name.replaceAll(" ", "%20");

					if (name.endsWith(".xml") && !isEmpty(odfZipInputStream)) {
						/* apply transformation on non-empty XML files only */
						referenceInfos.add(new ReferenceInfo(uri,
								CanonicalizationMethod.INCLUSIVE));
					} else {
						referenceInfos.add(new ReferenceInfo(uri, null));
					}
					LOG.debug("entry: " + name);
				}
			}
		} catch (IOException e) {
			LOG.error("IO error: " + e.getMessage(), e);
		} catch (Exception e) {
			LOG.error("Error: " + e.getMessage(), e);
		}
		return referenceInfos;
	}

	/**
	 * Unfortunately zipEntry.getSize() often returns -1/size unknown, so this
	 * is a quick hack to see if the file is empty or not
	 * 
	 * @param inputStream
	 * @return
	 * @throws IOException
	 */
	private boolean isEmpty(InputStream inputStream) throws IOException {
		return 0 == inputStream.skip(1);
	}

	/**
	 * Returns the URL of the ODF to be signed.
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
		return "ODF Document";
	}

	@Override
	protected final OutputStream getSignedDocumentOutputStream() {
		LOG.debug("get signed document output stream");
		/*
		 * Create each time a new object; we want an empty output stream to
		 * start with.
		 */
		OutputStream signedDocumentOutputStream = new ODFSignedDocumentOutputStream();
		return signedDocumentOutputStream;
	}

	private class ODFSignedDocumentOutputStream extends ByteArrayOutputStream {

		@Override
		public void close() throws IOException {
			LOG.debug("close ODF signed document output stream");
			super.close();
			outputSignedOpenDocument(this.toByteArray());
		}
	}

	private void outputSignedOpenDocument(byte[] signatureData)
			throws IOException {
		LOG.debug("output signed open document");
		OutputStream signedOdfOutputStream = getSignedOpenDocumentOutputStream();
		if (null == signedOdfOutputStream) {
			throw new NullPointerException(
					"signedOpenDocumentOutputStream is null");
		}
		/*
		 * Copy the original ODF content to the signed ODF package.
		 */
		ZipOutputStream zipOutputStream = new ZipOutputStream(
				signedOdfOutputStream);
		ZipInputStream zipInputStream = new ZipInputStream(this
				.getOpenDocumentURL().openStream());
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (!zipEntry.getName().equals(ODFUtil.SIGNATURE_FILE)) {
				zipOutputStream.putNextEntry(zipEntry);
				IOUtils.copy(zipInputStream, zipOutputStream);
			}
		}
		zipInputStream.close();
		/*
		 * Add the ODF XML signature file to the signed ODF package.
		 */
		zipEntry = new ZipEntry(ODFUtil.SIGNATURE_FILE);
		zipOutputStream.putNextEntry(zipEntry);
		IOUtils.write(signatureData, zipOutputStream);
		zipOutputStream.close();
	}

	/**
	 * The output stream to which to write the signed ODF file.
	 * 
	 * @return
	 */
	abstract protected OutputStream getSignedOpenDocumentOutputStream();

	public final String getFilesDigestAlgorithm() {
		/*
		 * No local files to digest.
		 */
		return null;
	}

	@Override
	protected final Document getEnvelopingDocument()
			throws ParserConfigurationException, IOException, SAXException {
		Document document = getODFSignatureDocument();
		if (null != document) {
			return document;
		}
		document = ODFUtil.getNewDocument();
		Element rootElement = document.createElementNS(ODFUtil.SIGNATURE_NS,
				ODFUtil.SIGNATURE_ELEMENT);
		rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns",
				ODFUtil.SIGNATURE_NS);
		document.appendChild(rootElement);
		return document;
	}

	/**
	 * Get the XML signature file from the ODF package
	 * 
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 */
	private Document getODFSignatureDocument() throws IOException,
			ParserConfigurationException, SAXException {
		URL odfUrl = this.getOpenDocumentURL();

		InputStream inputStream = ODFUtil.findDataInputStream(odfUrl
				.openStream(), ODFUtil.SIGNATURE_FILE);
		if (null != inputStream) {
			return ODFUtil.loadDocument(inputStream);
		}
		return null;
	}
}
