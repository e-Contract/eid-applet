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

package be.fedict.eid.applet.service.signer.odf;

import java.io.InputStream;
import java.io.IOException;

import java.net.URL;

import java.util.ArrayList;
import java.util.List;

import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.SAXException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Helper class to remove some code duplication
 *
 * @author Bart Hanssens
 */
public class ODFUtil {
    public static String MANIFEST_FILE = "META-INF/manifest.xml";
    public static String MIMETYPE_FILE = "mimetype";
    public static String MIMETYPE_START = "application/vnd.oasis.opendocument";
    public static String SIGNATURE_FILE = "META-INF/documentsignatures.xml";
    public static String SIGNATURE_NS = 
            "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
    public static String SIGNATURE_ELEMENT = "document-signatures";

    private static final Log LOG = LogFactory.getLog(ODFUtil.class);

     /**
     * Load an XML file from ODF package as a DOM Document
     *
     * @param documentInputStream
     * @return
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    public static Document loadDocument(InputStream documentInputStream)
            throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilder documentBuilder = getNewDocumentBuilder();
        Document document = documentBuilder.parse(documentInputStream);
        return document;
    }

    /**
     * Return a new DOM Document
     *
     * @return DOM Document
     * @throws ParserConfigurationException
     */
    public static Document getNewDocument() throws ParserConfigurationException {
        return getNewDocumentBuilder().newDocument();
    }

    /**
     * Return a new DOM Document Builder
     *
     * @return DOM Document Builder
     * @throws ParserConfigurationException
     */
    public static DocumentBuilder getNewDocumentBuilder() throws ParserConfigurationException {
        LOG.debug("new DOM document builder");
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        return documentBuilderFactory.newDocumentBuilder();
    }

    /**
     * Read the zipped data in the ODF package and return the inputstream
     * for a given file / zip entry
     *
     * @param inputStream
     * @param uri
     * @return inputstream for the file / zip entry
     * @throws IOException
     */
    protected static InputStream findDataInputStream(InputStream inputStream,
            String uri) throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(inputStream);
        ZipEntry zipEntry;
        while (null != (zipEntry = zipInputStream.getNextEntry())) {
            if (zipEntry.getName().equals(uri)) {
                return zipInputStream;
            }
	}
	return null;
    }


    /**
     * Checks if a file / zip entry is a content file
     *
     * @param zipEntry
     * @return true if zip entry is a content file
     */
    protected static boolean isContentFile(ZipEntry zipEntry) {
        /* should be enough for most simple ODF files and ODF embedded into
         another ODF file (e.g. chart in spreadsheet) */
        return zipEntry.getName().endsWith("content.xml");
    }

    /**
     * Checks if a file / zip entry is a signature file
     *
     * @param zipEntry
     * @return true if zip entry is a signature file
     */
    protected static boolean isSignatureFile(ZipEntry zipEntry) {
        /* for now, only check for document signatures,
           not the other macro signatures or application specific signatures */
        return zipEntry.getName().equals(SIGNATURE_FILE);
    }


    /**
     * Check if a file / zip entry is to be signed
     *
     * @param zipEntry
     * @return true if zip entry is to be signed
     */
    protected static boolean isToBeSigned(ZipEntry zipEntry) {
        String name = zipEntry.getName();

        /* OOo 3.0/3.1 bug: don't sign mimetype stream nor the manifest */
        /* if (zipEntry.isDirectory() ||
             name.equals(MIMETYPE_FILE) ||
             name.equals(MANIFEST_FILE) || */
        /* Corrected in OOo 3.2 */

        if (zipEntry.isDirectory() || name.equals(SIGNATURE_FILE)) {
            return false;
        }
        return true;
    }

    /**
     * Get a list of all the files / zip entries in an ODF package 
     * @param odfUrl
     * @return
     * @throws IOException
     */
    protected static List getZipEntriesAsList(InputStream odfInputStream) throws IOException {
        ArrayList list = new ArrayList();

        ZipInputStream odfZipInputStream = new ZipInputStream(odfInputStream);
        ZipEntry zipEntry;

        while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
            list.add(zipEntry.getName());
        }
        return list;
    }

    /**
     * Check if an ODF package is self-contained, i.e. content files don't have 
     * OLE objects linked to external files
     *
     * @param odfUrl
     * @return
     * @throws IOException
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws XPathExpressionException
     */
    public static boolean isSelfContained(URL odfUrl)
            throws IOException, ParserConfigurationException, SAXException, XPathExpressionException {
        InputStream odfInputStream = odfUrl.openStream();
        List zipEntries = getZipEntriesAsList(odfInputStream);

        odfInputStream = odfUrl.openStream();
        ZipInputStream odfZipInputStream = new ZipInputStream(odfInputStream);
        ZipEntry zipEntry;

        XPathFactory factory = XPathFactory.newInstance();
        /* Maybe a bit overkill, but implementations can use other prefixes */
        ODFNamespaceContext namespaceContext = new ODFNamespaceContext();

        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(namespaceContext);
        XPathExpression expression =  xpath.compile(
                "//draw:object/@xlink:href|" +
                "//draw:object-ole/@xlink:href|" +
                "//draw:image/@xlink:href|" +
                "//draw:floating-frame/@xlink:href");

        while (null != (zipEntry = odfZipInputStream.getNextEntry())) {
            if (isContentFile(zipEntry)) {
                /* TODO: pure SAX is probably more memory-efficient */
                Document content = ODFUtil.loadDocument(odfZipInputStream);
                NodeList nodes = (NodeList)
                        expression.evaluate(content, XPathConstants.NODESET);
                return checkNodes(nodes, zipEntries);
            }
        }
        return true;
    }

    protected static boolean checkNodes(NodeList nodes, List zipEntries) {
        for (int i = 0; i < nodes.getLength(); i++) {
            String url = nodes.item(i).getNodeValue();
            if ("".equals(url)) {
                LOG.debug("Skip empty xlink:href");
                continue;
            }
            if (url.startsWith("./")) {
                url = url.substring(2);
            }
            /* check if inside package or not */
            if (! zipEntries.contains(url)) {
                LOG.debug("Not self-contained: " + url + " outside package");
                return false;
            }
        }
        return true;
    }
}
