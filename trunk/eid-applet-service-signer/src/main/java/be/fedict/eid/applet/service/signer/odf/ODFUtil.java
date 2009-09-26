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

import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Helper class to remove some code duplication
 *
 * @author Bart Hanssens
 */
public class ODFUtil {
    private static final Log LOG = LogFactory.getLog(ODFUtil.class);

    /**
     * Return a new DOM Document
     *
     * @return DOM Document
     * @throws ParserConfigurationException
     */
    public static Document getNewDocument() throws ParserConfigurationException {
        LOG.debug("new documnet");
        return getNewDocumentBuilder().newDocument();
    }

    /**
     * Return a new DOM Document Builder
     *
     * @return DOM Document Builder
     * @throws ParserConfigurationException
     */
    public static DocumentBuilder getNewDocumentBuilder() throws ParserConfigurationException {
        LOG.debug("new document builder");
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        return documentBuilderFactory.newDocumentBuilder();
    }

    /**
     * Checks if a file / zip entry is a signature file
     *
     * @param zipEntry
     * @return true if zip entry is a signature file
     */
    protected static boolean isSignatureFile(ZipEntry zipEntry) {
        /* for now, only check for document signatures,
           not for other macro signatures or application specific signatures */
        return zipEntry.getName().equals("META-INF/documentsignatures.xml");
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
}
