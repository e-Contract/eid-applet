/*
 * eID Applet Project.
 * Copyright (C) 2015 e-Contract.be BVBA.
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

package be.fedict.eid.applet.service.impl.tlv;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CountryOfProtectionDataConvertor implements DataConvertor<String> {

	private static final Log LOG = LogFactory
			.getLog(DateOfProtectionDataConvertor.class);

	@Override
	public String convert(byte[] value) throws DataConvertorException {
		byte[] country = new byte[2];
		try {
			System.arraycopy(value, 11, country, 0, 2);
			return new String(country);
		} catch (Exception e) {
			LOG.error("error parsing CountryOfProtection: " + e.getMessage(), e);
			return null;
		}
	}
}
