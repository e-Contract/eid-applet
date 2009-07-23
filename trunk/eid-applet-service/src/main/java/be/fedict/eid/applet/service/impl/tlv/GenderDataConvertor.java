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

import be.fedict.eid.applet.service.Gender;

/**
 * Data convertor for gender data type.
 * 
 * @author fcorneli
 * 
 */
public class GenderDataConvertor implements DataConvertor<Gender> {

	public Gender convert(byte[] value) throws DataConvertorException {
		String genderStr = new String(value);
		if ("M".equals(genderStr)) {
			return Gender.MALE;
		}
		if ("F".equals(genderStr)) {
			return Gender.FEMALE;
		}
		if ("V".equals(genderStr)) {
			return Gender.FEMALE;
		}
		if ("W".equals(genderStr)) {
			return Gender.FEMALE;
		}
		throw new DataConvertorException("unknown gender: " + genderStr);
	}

}
