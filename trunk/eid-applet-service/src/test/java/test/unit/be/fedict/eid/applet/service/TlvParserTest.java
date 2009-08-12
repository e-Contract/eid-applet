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

package test.unit.be.fedict.eid.applet.service;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.GregorianCalendar;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Gender;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.impl.tlv.TlvField;
import be.fedict.eid.applet.service.impl.tlv.TlvParser;

public class TlvParserTest {

	private static final Log LOG = LogFactory.getLog(TlvParserTest.class);

	@Test
	public void parseIdentityFile() throws Exception {
		// setup
		InputStream idInputStream = TlvParserTest.class
				.getResourceAsStream("/id-alice.tlv");
		byte[] idFile = IOUtils.toByteArray(idInputStream);

		// operate
		Identity identity = TlvParser.parse(idFile, Identity.class);

		// verify
		assertNotNull(identity);
		LOG.debug("name: " + identity.name);
		assertEquals("SPECIMEN", identity.name);
		LOG.debug("first name: " + identity.firstName);
		assertEquals("Alice Geldigekaart2266", identity.firstName);
		LOG.debug("card number: " + identity.cardNumber);
		assertEquals("000000226635", identity.cardNumber);
		LOG.debug("card validity date begin: "
				+ identity.cardValidityDateBegin.getTime());
		assertEquals(new GregorianCalendar(2005, 7, 8),
				identity.cardValidityDateBegin);
		LOG.debug("card validity date end: "
				+ identity.cardValidityDateEnd.getTime());
		assertEquals(new GregorianCalendar(2010, 7, 8),
				identity.cardValidityDateEnd);
		LOG.debug("Card Delivery Municipality: "
				+ identity.cardDeliveryMunicipality);
		assertEquals("Certipost Specimen", identity.cardDeliveryMunicipality);
		LOG.debug("national number: " + identity.nationalNumber);
		assertEquals("71715100070", identity.nationalNumber);
		LOG.debug("middle name: " + identity.middleName);
		assertEquals("A", identity.middleName);
		LOG.debug("nationality: " + identity.nationality);
		assertEquals("Belg", identity.nationality);
		LOG.debug("place of birth: " + identity.placeOfBirth);
		assertEquals("Hamont-Achel", identity.placeOfBirth);
		LOG.debug("gender: " + identity.gender);
		assertEquals(Gender.FEMALE, identity.gender);
		assertNotNull(identity.dateOfBirth);
		LOG.debug("date of birth: " + identity.dateOfBirth.getTime());
		assertEquals(new GregorianCalendar(1971, 0, 1), identity.dateOfBirth);
	}

	@Test
	public void parseIdentityFile2() throws Exception {
		// setup
		InputStream idInputStream = TlvParserTest.class
				.getResourceAsStream("/id-alice-2.tlv");
		byte[] idFile = IOUtils.toByteArray(idInputStream);

		// operate
		Identity identity = TlvParser.parse(idFile, Identity.class);

		// verify
		assertNotNull(identity);
		LOG.debug("name: " + identity.name);
		assertEquals("SPECIMEN", identity.name);
		LOG.debug("first name: " + identity.firstName);
		assertEquals("Alice Geldigekaart0126", identity.firstName);
		LOG.debug("card number: " + identity.cardNumber);
		assertEquals("000000012629", identity.cardNumber);
		LOG.debug("card validity date begin: "
				+ identity.cardValidityDateBegin.getTime());
		assertEquals(new GregorianCalendar(2003, 9, 24),
				identity.cardValidityDateBegin);
		LOG.debug("card validity date end: "
				+ identity.cardValidityDateEnd.getTime());
		assertEquals(new GregorianCalendar(2008, 9, 24),
				identity.cardValidityDateEnd);
		LOG.debug("Card Delivery Municipality: "
				+ identity.cardDeliveryMunicipality);
		assertEquals("Certipost Specimen", identity.cardDeliveryMunicipality);
		LOG.debug("national number: " + identity.nationalNumber);
		assertEquals("71715100070", identity.nationalNumber);
		LOG.debug("middle name: " + identity.middleName);
		assertEquals("A", identity.middleName);
		LOG.debug("nationality: " + identity.nationality);
		assertEquals("Belg", identity.nationality);
		LOG.debug("place of birth: " + identity.placeOfBirth);
		assertEquals("Hamont-Achel", identity.placeOfBirth);
		LOG.debug("gender: " + identity.gender);
		assertEquals(Gender.FEMALE, identity.gender);
		assertNotNull(identity.dateOfBirth);
		LOG.debug("date of birth: " + identity.dateOfBirth.getTime());
		assertEquals(new GregorianCalendar(1971, 0, 1), identity.dateOfBirth);
	}

	@Test
	public void parseAddressFile() throws Exception {
		// setup
		InputStream addressInputStream = TlvParserTest.class
				.getResourceAsStream("/address-alice.tlv");
		byte[] addressFile = IOUtils.toByteArray(addressInputStream);

		// operate
		Address address = TlvParser.parse(addressFile, Address.class);

		// verify
		assertNotNull(address);
		LOG.debug("street and number: " + address.streetAndNumber);
		assertEquals("Meirplaats 1 bus 1", address.streetAndNumber);
		LOG.debug("zip: " + address.zip);
		assertEquals("2000", address.zip);
		LOG.debug("municipality: " + address.municipality);
		assertEquals("Antwerpen", address.municipality);
	}

	public static class LargeField {
		@TlvField(1)
		public byte[] field1;

		@TlvField(2)
		public byte[] field2;
	}

	@Test
	public void testLargeField() throws Exception {
		// setup
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		byteStream.write(1);
		byteStream.write(255);
		byteStream.write(250);
		for (int i = 0; i < 255 + 250; i++) {
			byteStream.write(0x12);
		}
		byteStream.write(2);
		byteStream.write(4);
		byteStream.write(0xca);
		byteStream.write(0xfe);
		byteStream.write(0xba);
		byteStream.write(0xbe);
		byte[] file = byteStream.toByteArray();

		// operate
		LargeField largeField = TlvParser.parse(file, LargeField.class);

		// verify
		assertEquals(255 + 250, largeField.field1.length);
		assertArrayEquals(new byte[] { (byte) 0xca, (byte) 0xfe, (byte) 0xba,
				(byte) 0xbe }, largeField.field2);
	}
}
