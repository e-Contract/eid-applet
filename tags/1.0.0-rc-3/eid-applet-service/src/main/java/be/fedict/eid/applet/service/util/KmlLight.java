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


package be.fedict.eid.applet.service.util;

import java.io.IOException;
import java.io.OutputStream;

import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A "light" implementation of OGC standard KML 2.2
 * This class merely creates the KMZ zip package
 *
 * @see http://www.opengeospatial.org/standards/kml/
 * @author Bart Hanssens
 */
public class KmlLight {
    private static final Log LOG = LogFactory.getLog(KmlLight.class);

    /* yes, this is the correct MIME TYPE used by OGC standard */
    public static final String MIME_TYPE = "application/vnd.google-earth.kmz";
    private ZipOutputStream kmz;

    /**
     * Add an image (photo) to the KMZ zip
     *
     * @param image
     * @throws IOException
     */
    public void addImage(byte[] image) throws IOException {
        ZipEntry zImage = new ZipEntry("photo.jpg");
        kmz.putNextEntry(zImage);
        kmz.write(image);
        kmz.closeEntry();
    }

    /**
     * Add the KML file to the KMZ zip
     *
     * @param doc KML document
     * @throws IOException
     */
    public void addKmlFile(byte[] doc) throws IOException {
        ZipEntry zKml = new ZipEntry("data.kml");
        kmz.putNextEntry(zKml);
        kmz.write(doc);
        kmz.closeEntry();
    }

    /**
     * Close the KMZ zip file
     *
     * @throws IOException
     */
    public void close() throws IOException {
        kmz.close();
    }

    /**
     * Constructor
     *
     * @param outStream
     */
    public KmlLight(OutputStream outStream) {
        kmz = new ZipOutputStream(outStream);
    }

}
