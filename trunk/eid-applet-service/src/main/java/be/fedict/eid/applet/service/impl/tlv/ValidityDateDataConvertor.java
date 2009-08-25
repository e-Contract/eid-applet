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

import java.util.GregorianCalendar;

/**
 * Data convertor for eID identity validity dates.
 * 
 * @author Frank Cornelis
 * 
 */
public class ValidityDateDataConvertor implements
		DataConvertor<GregorianCalendar> {

	public GregorianCalendar convert(byte[] value)
			throws DataConvertorException {
		String dateStr = new String(value);
		int day = Integer.parseInt(dateStr.substring(0, 2));
		int month = Integer.parseInt(dateStr.substring(3, 5));
		int year = Integer.parseInt(dateStr.substring(6));
		GregorianCalendar calendar = new GregorianCalendar(year, month - 1, day);
		return calendar;
	}
}
