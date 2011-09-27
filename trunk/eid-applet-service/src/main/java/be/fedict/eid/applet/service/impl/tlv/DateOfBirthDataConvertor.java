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

import java.io.UnsupportedEncodingException;
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
		String dateOfBirthStr;
		try {
			dateOfBirthStr = new String(value, "UTF-8").trim();
		} catch (UnsupportedEncodingException e) {
			throw new DataConvertorException("UTF-8 not supported");
		}
		LOG.debug("\"" + dateOfBirthStr + "\"");
		/*
		 * First try to detect the German format as there are cases in which a
		 * German format contains both dots and spaces.
		 */
		int spaceIdx = dateOfBirthStr.indexOf('.');
		if (-1 == spaceIdx) {
			spaceIdx = dateOfBirthStr.indexOf(' ');
		}

		if (spaceIdx > 0) {
			String dayStr = dateOfBirthStr.substring(0, spaceIdx);
			LOG.debug("day: \"" + dayStr + "\"");
			int day = Integer.parseInt(dayStr);
			String monthStr = dateOfBirthStr.substring(spaceIdx + 1,
					dateOfBirthStr.length() - 4 - 1);
			if (monthStr.endsWith(".")) {
				monthStr = monthStr.substring(0, monthStr.length() - 1);
			}
			LOG.debug("month: \"" + monthStr + "\"");
			String yearStr = dateOfBirthStr
					.substring(dateOfBirthStr.length() - 4);
			LOG.debug("year: \"" + yearStr + "\"");
			int year = Integer.parseInt(yearStr);
			int month = toMonth(monthStr);
			return new GregorianCalendar(year, month, day);
		}

		if (dateOfBirthStr.length() == 4) {
			/*
			 * "case II2b2". Only a birth year is given
			 * 
			 * there's no way of representing "missing" fields via
			 * GregorianCalendar, so we set Jan 1st
			 */
			return new GregorianCalendar(Integer.parseInt(dateOfBirthStr), 0, 1);
		}

		throw new DataConvertorException("Unsupported Birth Date Format ["
				+ dateOfBirthStr + "]");
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
