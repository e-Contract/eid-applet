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
import java.io.PrintWriter;

import java.text.SimpleDateFormat;

import java.util.Date;

import org.apache.commons.codec.binary.Base64;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A light implementation of VCard 3.0
 *
 * @see http://www.ietf.org/rfc/rfc2426.txt
 * @author Bart Hanssens
 */
public class VcardLight {
    private static final Log LOG = LogFactory.getLog(VcardLight.class);

    /* correct MIME type, not text/x-vcard */
    public static final String MIME_TYPE = "text/directory;profile=vCard";

    private PrintWriter vcard;


    /**
     * Start the VCard
     */
    public void open() {
        vcard.println("BEGIN:vCARD");
        vcard.println("VERSION:3.0");
    }

    /**
     * Add the name info
     *
     * @param firstName first name
     * @param middleName middle name, if any
     * @param name last name
     */
    public void addName(String firstName, String middleName, String name) {
        String nameFN = firstName + " " + name;

        String nameN = name + ";" + firstName +";";
        nameN += (null != middleName) ? middleName + ";" : ";";

        /* empty prefix + empty suffix */
        /*nameN += ";"; */

        vcard.println("FN:" + nameFN);
        vcard.println("N:" + nameN);
    }

    /**
     * Add the citizen's home address
     *
     * @param streetNo street and number
     * @param zip zip code
     * @param municipality name of the municipality / city
     */
    public void addAddress(String streetNo, String zip, String municipality) {
        /* empty po box + empty extended address */
        String adr = ";;";

        adr += (null != streetNo) ? streetNo + ";" : ";";
        adr += (null != municipality) ? municipality + ";" : ";";
        /* empty region */
        adr += ";";
        adr += (null != zip) ? zip + ";" : ";";
        adr += "Belgium";

        vcard.println("ADR;TYPE=home:" + adr);
    }

    /**
     * Add day of birth
     *
     * @param birthday
     */
    public void addBorn(Date birthday) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
        String bday = fmt.format(birthday);

        vcard.println("BDAY:" + bday);
    }
    
    /**
     * Add an image (photo)
     *
     * @param image photo
     * @throws IOException
     */
    public void addImage(byte[] image) throws IOException {
        byte[] enc = Base64.encodeBase64(image);
        String str = "PHOTO;ENCODING=b;TYPE=JPEG:" + new String(enc);
        int length = str.length();


        /* can be simplified when using Commons Codec 1.4 instead of 1.3 */
        if (length > 76) {
            /* chunk in lines, make sure the first line is also 76 chars  */
            StringBuffer buf = new StringBuffer();
            buf.append(str.substring(0, 76));

            /* add a space before 2nd, 3rd... */
            for (int i = 76; i < length; i += 75) {
                buf.append("\n ");
                if (length > i + 75) {
                    buf.append(str.substring(i, i + 75));
                } else {
                    buf.append(str.substring(i));
                }
            }
            vcard.println(buf.toString());
        }
    }

    /**
     * End of the vCard
     */
    public void close() {
        vcard.println("END:vCard");
        vcard.close();
    }
    /**
     * Constructor
     *
     * @param outStream
     */
    public VcardLight(OutputStream outStream) {
        vcard = new PrintWriter(outStream);
    }

}
