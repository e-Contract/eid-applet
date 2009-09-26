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

import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;

import org.jcp.xml.dsig.internal.dom.DOMKeyInfo;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.xml.sax.SAXException;

import be.fedict.eid.applet.service.signer.AbstractXmlSignatureService;

/**
 * Signature Service implementation for OpenDocument format signatures.
 *
 * The signatures created with this class are accepted as valid signature within
 * OpenOffice.org 3.x. They probably don't get accepted by older OOo versions.
 * 
 * <p>
 * See also <a href="http://www.openoffice.org/">OpenOffice.org</a>.
 * </p>
 * 
 * @author fcorneli
 * 
 */
abstract public class AbstractODFSignatureService extends AbstractXmlSignatureService {

    private static final Log LOG = LogFactory.getLog(AbstractODFSignatureService.class);

    public AbstractODFSignatureService() {
        super();
        addSignatureAspect(new OpenOfficeSignatureAspect());
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
                if (isToBeSigned(zipEntry)) {
                    String name = zipEntry.getName();
                    /* Whitespaces are illegal in URIs
                     *
                     * Note that OOo seems to have a bug, seems like the
                     * OOo signature verification doesn't convert it back to
                     * whitespace, to be investigated
                     */
                    String uri = name.replaceAll(" ", "%20");
                    LOG.debug("uri: " + uri);

                    if (name.endsWith(".xml") && !isEmpty(odfZipInputStream)) {
                        LOG.debug("non-empty entry: " + name);
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
            LOG.warn("IO error: " + e.getMessage(), e);
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


    /* Check if a file / zip entry is to be signed
     *
     * @param zipEntry
     * @return true if zip entry is to be signed
     */
    private static boolean isToBeSigned(ZipEntry zipEntry) {
        String name = zipEntry.getName();

        /* OOo 3.0/3.1 bug: don't sign mimetype stream nor the manifest */
        if (zipEntry.isDirectory() ||
                name.equals("mimetype") ||
                name.equals("META-INF/manifest.xml") ||
                name.equals("META-INF/documentsignatures.xml")) {
            return false;
        }
        return true;
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
        ZipInputStream zipInputStream = new ZipInputStream(this.getOpenDocumentURL().openStream());
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            if (! ODFUtil.isSignatureFile(zipEntry)) {
                zipOutputStream.putNextEntry(zipEntry);
                IOUtils.copy(zipInputStream, zipOutputStream);
            }
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
        // TODO: refactor as signature aspect
        LOG.debug("postSign");
        /*
         * Make sure we insert right after the ds:SignatureValue element.
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
         * Add a ds:KeyInfo entry.
         */
        KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance();
        List<Object> x509DataObjects = new LinkedList<Object>();
        X509Certificate signingCertificate = signingCertificateChain.get(0);
        x509DataObjects.add(keyInfoFactory.newX509IssuerSerial(
                signingCertificate.getIssuerX500Principal().toString(),
                signingCertificate.getSerialNumber()));
        /*
         * XXX: for the moment we only add the signing certificate because of a
         * bug in OpenOffice 3.1.
         */
        x509DataObjects.add(signingCertificate);
        X509Data x509Data = keyInfoFactory.newX509Data(x509DataObjects);
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
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
            domKeyInfo.marshal(signatureElement, nextSibling, dsPrefix,
                    domCryptoContext);
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
        document = ODFUtil.getNewDocument();
        Element rootElement = document.createElementNS(
                "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0",
                "document-signatures");
        rootElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns",
                "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0");
        document.appendChild(rootElement);
        return document;
    }

    private Document getODFSignatureDocument() throws IOException,
            ParserConfigurationException, SAXException {
        URL odfUrl = this.getOpenDocumentURL();
        ZipInputStream odfZipInputStream = new ZipInputStream(odfUrl.openStream());
        ZipEntry zipEntry;
        while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
            if (ODFUtil.isSignatureFile(zipEntry)) {
                return loadDocument(odfZipInputStream);
            }
        }
        return null;
    }
}
