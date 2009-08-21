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

package be.fedict.eid.applet.service.signer.ooxml;

import java.io.IOException;
import java.net.URL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Signature verifier util class for Office Open XML file format.
 * 
 * @author fcorneli
 * 
 */
public class OOXMLSignatureVerifier {

	private OOXMLSignatureVerifier() {
		super();
	}

	/**
	 * Checks whether the file referred by the given URL is an OOXML document.
	 * 
	 * @param url
	 * @return
	 * @throws IOException
	 */
	public static boolean isOOXML(URL url) throws IOException {
		ZipInputStream zipInputStream = new ZipInputStream(url.openStream());
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (false == "[Content_Types].xml".equals(zipEntry.getName())) {
				continue;
			}
			if (zipEntry.getSize() > 0) {
				return true;
			}
		}
		return false;
	}
}
