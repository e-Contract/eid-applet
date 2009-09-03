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

package be.fedict.eid.applet.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.Identity;

import be.fedict.eid.applet.service.util.KmlLight;
import be.fedict.eid.applet.service.util.KmlLightDocument;

import org.w3c.dom.Element;

/**
 * KML generator for eID identity data. The implementation is using a "light"
 * implementation
 * 
 * @author Bart Hanssens
 * @see KmlServlet
 */
public class KmlGenerator {
    private static final Log LOG = LogFactory.getLog(KmlGenerator.class);

    /**
     * Generate zipped KML (.kmz) using data from the eID card
     *
     * @param eIdData ID data retrieved from eID card
     * @return KMZ as raw bytes
     * @throws IOException
     */
    public byte[] generateKml(EIdData eIdData) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        KmlLight kml = new KmlLight(baos);
        KmlLightDocument doc = new KmlLightDocument();

        String htmlDescription = "";

        if (null != eIdData && null != eIdData.getIdentity()) {
            Identity identity = eIdData.getIdentity();

            if (null != eIdData.getPhoto()) {
                byte[] photoData = eIdData.getPhoto();
                kml.addImage(photoData);
                htmlDescription += "<img src='photo.jpg' align='left'>";
            } else {
                LOG.debug("no photo");
            }

            Element elName = doc.createName(identity.firstName + " " + identity.name);

            /* name */
            htmlDescription += identity.firstName + " ";
            if (null != identity.middleName) {
                htmlDescription += identity.middleName + " ";
            }
            htmlDescription += identity.name;
            htmlDescription += "<br/>";

            /* nationality */
            htmlDescription += identity.nationality;
            htmlDescription += "<br/>";

            /* day of birth */
            SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String birthday = formatter.format(identity.dateOfBirth.getTime());
            htmlDescription += "(°" + birthday + ", " + identity.placeOfBirth + ")";
            htmlDescription += "<br/>";

            /* validity of the card */
            Element elValid = null;

            if (null != identity.cardValidityDateBegin) {
                elValid = doc.createTimespan(identity.cardValidityDateBegin.getTime(),
                                        identity.cardValidityDateEnd.getTime());
            } else {
                LOG.debug("card validity begin date is unknown");
            }

            /* citizen's address */
            Element elAddress = null;

            if (null != eIdData.getAddress()) {
                Address address = eIdData.getAddress();

                /* not needed, or it will appear twice in GoogleEarth
                htmlDescription += address.streetAndNumber + ", " +
                        address.zip + " " + address.municipality;
                htmlDescription += "<br/>";
                */
                elAddress = doc.createAddress(address.streetAndNumber,
                        address.municipality, address.zip);
            } else {
                LOG.debug("no address");
            }

            Element elDescription = doc.createDescriptionNode(htmlDescription);
            doc.addPlacemark(elName, elAddress, elDescription, elValid);
        }
        kml.addKmlFile(doc.getDocumentAsBytes());
        kml.close();
        
        return baos.toByteArray();
    }
}
