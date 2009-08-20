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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.jcp.xml.dsig.internal.dom.DOMKeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Signature Service implementation for OpenDocument format signatures. The
 * signatures created with this class are accepted as valid signature within
 * OpenOffice.org.
 * 
 * <p>
 * See also <a href="http://www.openoffice.org/">OpenOffice.org</a>.
 * </p>
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
	protected List<ReferenceInfo> getReferences() {
		List<ReferenceInfo> referenceInfos = new LinkedList<ReferenceInfo>();
		URL odfUrl = this.getOpenDocumentURL();
		try {
			InputStream odfInputStream = odfUrl.openStream();
			ZipInputStream odfZipInputStream = new ZipInputStream(
					odfInputStream);
			ZipEntry zipEntry;
			while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
				if (true == zipEntry.isDirectory()) {
					continue;
				}
				if ("mimetype".equals(zipEntry.getName())) {
					continue;
				}
				if ("META-INF/manifest.xml".equals(zipEntry.getName())) {
					continue;
				}
				if ("META-INF/documentsignatures.xml"
						.equals(zipEntry.getName())) {
					continue;
				}
				String uri = zipEntry.getName().replaceAll(" ", "%20");
				LOG.debug("uri: " + uri);
				if (zipEntry.getName().endsWith(".xml")
						&& zipEntry.getSize() > 0) {
					/*
					 * On non-empty XML files we apply a transformation.
					 */
					referenceInfos.add(new ReferenceInfo(uri,
							CanonicalizationMethod.INCLUSIVE));
				} else {
					referenceInfos.add(new ReferenceInfo(uri, null));
				}
				LOG.debug("entry: " + zipEntry.getName());
			}
		} catch (IOException e) {
			LOG.warn("IO error: " + e.getMessage(), e);
		}
		return referenceInfos;
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
			if ("META-INF/documentsignatures.xml".equals(zipEntry.getName())) {
				continue;
			}
			zipOutputStream.putNextEntry(zipEntry);
			IOUtils.copy(zipInputStream, zipOutputStream);
		}
		zipInputStream.close();
		/*
		 * Add the ODF XML signature file to the signed ODF package.
		 */
		zipEntry = new ZipEntry("META-INF/documentsignatures.xml");
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
	protected void postSign(Element signatureElement,
			List<X509Certificate> signingCertificateChain) {
		LOG.debug("postSign");
		/*
		 * Add a ds:KeyInfo entry.
		 */
		KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance();
		List<Object> x509DataObjects = new LinkedList<Object>();
		X509Certificate signingCertificate = signingCertificateChain.get(0);
		x509DataObjects.add(keyInfoFactory.newX509IssuerSerial(
				signingCertificate.getIssuerX500Principal().toString(),
				signingCertificate.getSerialNumber()));
		for (X509Certificate certificate : signingCertificateChain) {
			x509DataObjects.add(certificate);
		}
		X509Data x509Data = keyInfoFactory.newX509Data(x509DataObjects);
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections
				.singletonList(x509Data));
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
		// String dsPrefix = "ds";
		try {
			domKeyInfo.marshal(signatureElement, dsPrefix, domCryptoContext);
		} catch (MarshalException e) {
			throw new RuntimeException("marshall error: " + e.getMessage(), e);
		}
	}

	@Override
	protected final Document getEnvelopingDocument()
			throws ParserConfigurationException, IOException, SAXException {
		Document document = getODFSignatureDocument();
		if (null != document) {
			return document;
		}
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		document = documentBuilder.newDocument();
		Element rootElement = document.createElementNS(
				"urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0",
				"dsig:document-signatures");
		// next is required for correct validation in Java, but fails in OOo
		rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:dsig",
				"urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0");
		document.appendChild(rootElement);
		return document;
	}

	private Document getODFSignatureDocument() throws IOException,
			ParserConfigurationException, SAXException {
		URL odfUrl = this.getOpenDocumentURL();
		ZipInputStream odfZipInputStream = new ZipInputStream(odfUrl
				.openStream());
		ZipEntry zipEntry;
		while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
			if (false == "META-INF/documentsignatures.xml".equals(zipEntry
					.getName())) {
				continue;
			}
			Document document = loadDocument(odfZipInputStream);
			return document;
		}
		return null;
	}
}
