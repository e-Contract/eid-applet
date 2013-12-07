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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.EIdData;
import be.fedict.eid.applet.service.Identity;

import be.fedict.eid.applet.service.util.VcardLight;

/**
 * vCard generator for eID identity data. The implementation is using a "light"
 * implementation
 * 
 * @author Bart Hanssens
 * @see VcardServlet
 */
public class VcardGenerator {
    private static final Log LOG = LogFactory.getLog(VcardGenerator.class);

    /**
     * Generate vCard using data from the eID card
     *
     * @param eIdData ID data retrieved from eID card
     * @return vCard as raw bytes
     * @throws IOException
     */
    public byte[] generateVcard(EIdData eIdData) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        VcardLight vcard = new VcardLight(baos);
        vcard.open();

        if (null != eIdData && null != eIdData.getIdentity()) {
            Identity identity = eIdData.getIdentity();

            vcard.addName(identity.firstName, identity.middleName,
                    identity.name);

            if (null != eIdData.getAddress()) {
                Address address = eIdData.getAddress();
                vcard.addAddress(address.streetAndNumber, address.zip,
                        address.municipality);
            } else {
                LOG.debug("no address");
            }
            vcard.addBorn(identity.dateOfBirth.getTime());

            if (null != eIdData.getPhoto()) {
                byte[] photoData = eIdData.getPhoto();
		vcard.addImage(photoData);
            } else {
                LOG.debug("no photo");
            }
        }
        vcard.close();
        
        return baos.toByteArray();
    }
}
