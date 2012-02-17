/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

import java.io.UnsupportedEncodingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.SpecialOrganisation;

/**
 * Data convertor for special organisation eID identity field.
 * 
 * @author Frank Cornelis
 * 
 */
public class SpecialOrganisationConvertor implements
		DataConvertor<SpecialOrganisation> {

	private static final Log LOG = LogFactory
			.getLog(SpecialOrganisationConvertor.class);

	public SpecialOrganisation convert(byte[] value)
			throws DataConvertorException {
		if (null == value) {
			return SpecialOrganisation.UNSPECIFIED;
		}
		String key;
		try {
			key = new String(value, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new DataConvertorException("string error: " + e.getMessage());
		}
		LOG.debug("key: \"" + key + "\"");
		SpecialOrganisation specialOrganisation = SpecialOrganisation
				.toSpecialOrganisation(key);
		return specialOrganisation;
	}
}
