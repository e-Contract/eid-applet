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

package be.fedict.eid.applet.service.impl.tlv;

import org.apache.commons.codec.binary.Hex;

/**
 * Convertor for the chip number field.
 * 
 * @author Frank Cornelis
 * 
 */
public class ChipNumberDataConvertor implements DataConvertor<String> {

	public String convert(byte[] value) throws DataConvertorException {
		String chipNumber = new String(Hex.encodeHex(value)).toUpperCase();
		return chipNumber;
	}
}
