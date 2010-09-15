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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.GregorianCalendar;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.DocumentType;
import be.fedict.eid.applet.service.Gender;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.SpecialStatus;
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
		LOG.debug("special status: " + identity.specialStatus);
		assertEquals(SpecialStatus.NO_STATUS, identity.specialStatus);
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
	public void testYellowCane() throws Exception {
		// setup
		byte[] idFile = IOUtils.toByteArray(TlvParserTest.class
				.getResourceAsStream("/yellow-cane.tlv"));

		// operate
		Identity identity = TlvParser.parse(idFile, Identity.class);

		// verify
		LOG.debug("special status: " + identity.specialStatus);
		assertEquals(SpecialStatus.YELLOW_CANE, identity.specialStatus);
		assertTrue(identity.specialStatus.hasBadSight());
		assertTrue(identity.specialStatus.hasYellowCane());
		assertFalse(identity.specialStatus.hasWhiteCane());
	}

	@Test
	public void testWhiteCane() throws Exception {
		// setup
		byte[] idFile = IOUtils.toByteArray(TlvParserTest.class
				.getResourceAsStream("/white-cane.tlv"));

		// operate
		Identity identity = TlvParser.parse(idFile, Identity.class);

		// verify
		LOG.debug("special status: " + identity.specialStatus);
		assertEquals(SpecialStatus.WHITE_CANE, identity.specialStatus);
		assertTrue(identity.specialStatus.hasBadSight());
		assertTrue(identity.specialStatus.hasWhiteCane());
		assertFalse(identity.specialStatus.hasYellowCane());
	}

	@Test
	public void testExtendedMinority() throws Exception {
		// setup
		byte[] idFile = IOUtils.toByteArray(TlvParserTest.class
				.getResourceAsStream("/extended-minority.tlv"));

		// operate
		Identity identity = TlvParser.parse(idFile, Identity.class);

		// verify
		LOG.debug("special status: " + identity.specialStatus);
		assertEquals(SpecialStatus.EXTENDED_MINORITY, identity.specialStatus);
		assertFalse(identity.specialStatus.hasBadSight());
		assertTrue(identity.specialStatus.hasExtendedMinority());
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

		@TlvField(100)
		public byte[] field2;
	}

	@Test
	public void testLargeField() throws Exception {
		// setup
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

		// field length < 0x80
		byteStream.write(1); // tag
		byteStream.write(0x7f); // length
		for (int i = 0; i < 0x7f; i++) {
			byteStream.write(0x12); // data
		}

		// field length = 0x80
		byteStream.write(2); // tag
		byteStream.write(0x81); // length
		byteStream.write(0x00);
		for (int i = 0; i < 0x80; i++) {
			byteStream.write(0x34); // data
		}

		// field length = 0x3fff
		byteStream.write(3); // tag
		byteStream.write(0xff); // length
		byteStream.write(0x7f);
		for (int i = 0; i < 0x3fff; i++) {
			byteStream.write(0x56); // data
		}

		// field length = 0x4000
		byteStream.write(4); // tag
		byteStream.write(0x81); // length
		byteStream.write(0x80);
		byteStream.write(0x00);
		for (int i = 0; i < 0x4000; i++) {
			byteStream.write(0x78); // data
		}

		// our check field
		byteStream.write(100);
		byteStream.write(4);
		byteStream.write(0xca);
		byteStream.write(0xfe);
		byteStream.write(0xba);
		byteStream.write(0xbe);
		byte[] file = byteStream.toByteArray();

		// operate
		LargeField largeField = TlvParser.parse(file, LargeField.class);

		// verify
		assertEquals(0x7f, largeField.field1.length);
		assertArrayEquals(new byte[] { (byte) 0xca, (byte) 0xfe, (byte) 0xba,
				(byte) 0xbe }, largeField.field2);
	}

	public static class MiddlewareEIDFile {
		@TlvField(1)
		public byte[] identityFile;
	}

	@Test
	public void testParseMiddlewareEIDFile() throws Exception {
		byte[] eidFile = IOUtils.toByteArray(TlvParserTest.class
				.getResourceAsStream("/71715100070.eid"));
		MiddlewareEIDFile middlewareEIDFile = TlvParser.parse(eidFile,
				MiddlewareEIDFile.class);
		Identity identity = TlvParser.parse(middlewareEIDFile.identityFile,
				Identity.class);
		LOG.debug("identity: " + identity);
		LOG.debug("identity NRN: " + identity.nationalNumber);
		assertEquals("71715100070", identity.nationalNumber);
		LOG.debug("special status: " + identity.specialStatus);
	}

	@Test
	public void testForeignerIdentityFile() throws Exception {
		// setup
		InputStream inputStream = TlvParserTest.class
				.getResourceAsStream("/id-foreigner.tlv");
		byte[] identityData = IOUtils.toByteArray(inputStream);

		// operate
		Identity identity = TlvParser.parse(identityData, Identity.class);

		// verify
		LOG.debug("document type: " + identity.getDocumentType());
		assertEquals(DocumentType.FOREIGNER_E_PLUS, identity.getDocumentType());
	}

	@Test
	public void testParseOldIdentityFile() throws Exception {
		// setup
		InputStream inputStream = TlvParserTest.class
				.getResourceAsStream("/old-eid.txt");
		byte[] base64IdentityData = IOUtils.toByteArray(inputStream);
		byte[] identityData = Base64.decodeBase64(base64IdentityData);

		// operate
		Identity identity = TlvParser.parse(identityData, Identity.class);

		// verify
		LOG.debug("name: " + identity.getName());
		LOG.debug("first name: " + identity.getFirstName());
		LOG.debug("document type: " + identity.getDocumentType());
		LOG.debug("card validity date begin: "
				+ identity.getCardValidityDateBegin().getTime());
		assertEquals(DocumentType.BELGIAN_CITIZEN, identity.getDocumentType());
	}

	@Test
	public void testParseNewIdentityFile() throws Exception {
		// setup
		InputStream inputStream = TlvParserTest.class
				.getResourceAsStream("/new-eid.txt");
		byte[] base64IdentityData = IOUtils.toByteArray(inputStream);
		byte[] identityData = Base64.decodeBase64(base64IdentityData);

		// operate
		Identity identity = TlvParser.parse(identityData, Identity.class);

		// verify
		LOG.debug("name: " + identity.getName());
		LOG.debug("first name: " + identity.getFirstName());
		LOG.debug("card validity date begin: "
				+ identity.getCardValidityDateBegin().getTime());
		LOG.debug("document type: " + identity.getDocumentType());
		assertEquals(DocumentType.BELGIAN_CITIZEN, identity.getDocumentType());
	}

}
