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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Convertor for eID date of birth field.
 * 
 * @author Frank Cornelis
 * 
 */
public class DateOfBirthDataConvertor implements
		DataConvertor<GregorianCalendar> {

	private static final Log LOG = LogFactory
			.getLog(DateOfBirthDataConvertor.class);

	public GregorianCalendar convert(byte[] value)
			throws DataConvertorException {
		String dateOfBirthStr = new String(value);
		LOG.debug(dateOfBirthStr);
		int spaceIdx = dateOfBirthStr.indexOf(' ');
		String dayStr = dateOfBirthStr.substring(0, spaceIdx);
		int day = Integer.parseInt(dayStr);
		String monthStr = dateOfBirthStr.substring(spaceIdx + 1, dateOfBirthStr
				.length() - 4 - 1);
		String yearStr = dateOfBirthStr.substring(dateOfBirthStr.length() - 4);
		int year = Integer.parseInt(yearStr);
		int month = toMonth(monthStr);
		GregorianCalendar calendar = new GregorianCalendar(year, month, day);
		return calendar;
	}

	private static final String[][] MONTHS = new String[][] {
			new String[] { "JAN" }, new String[] { "FEV", "FEB" },
			new String[] { "MARS", "MAAR", "MÄR" },
			new String[] { "AVR", "APR" }, new String[] { "MAI", "MEI" },
			new String[] { "JUIN", "JUN" }, new String[] { "JUIL", "JUL" },
			new String[] { "AOUT", "AUG" }, new String[] { "SEPT", "SEP" },
			new String[] { "OCT", "OKT" }, new String[] { "NOV" },
			new String[] { "DEC", "DEZ" } };

	private int toMonth(String monthStr) throws DataConvertorException {
		monthStr = monthStr.trim();
		for (int monthIdx = 0; monthIdx < MONTHS.length; monthIdx++) {
			String[] monthNames = MONTHS[monthIdx];
			for (String monthName : monthNames) {
				if (monthName.equals(monthStr)) {
					return monthIdx;
				}
			}
		}
		throw new DataConvertorException("unknown month: " + monthStr);
	}
}
