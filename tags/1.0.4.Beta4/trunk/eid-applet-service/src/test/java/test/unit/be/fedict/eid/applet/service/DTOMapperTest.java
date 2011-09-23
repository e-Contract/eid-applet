/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.GregorianCalendar;

import org.junit.Test;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Gender;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.dto.DTOMapper;
import be.fedict.eid.applet.service.spi.AddressDTO;
import be.fedict.eid.applet.service.spi.IdentityDTO;

/**
 * Unit test for Data Transfer Object Mapper implementation.
 * 
 * @author Frank Cornelis
 * 
 */
public class DTOMapperTest {

	@Test
	public void testMapEmptyIdentity() throws Exception {
		// setup
		Identity identity = new Identity();

		DTOMapper dtoMapper = new DTOMapper();

		// operate
		IdentityDTO result = dtoMapper.map(identity, IdentityDTO.class);

		// verify
		assertNotNull(result);
	}

	@Test
	public void testMapIdentity() throws Exception {
		// setup
		Identity identity = new Identity();
		identity.firstName = "hello-world";
		identity.name = "test-name";
		identity.cardNumber = "card-number";
		identity.chipNumber = "chip-number";
		identity.dateOfBirth = new GregorianCalendar();
		identity.placeOfBirth = "place-of-birth";
		identity.nationality = "nationality";
		identity.middleName = "middle-name";
		identity.nationalNumber = "national-number";
		identity.cardDeliveryMunicipality = "cardDeliveryMunicipality";
		identity.cardValidityDateBegin = new GregorianCalendar();
		identity.cardValidityDateEnd = new GregorianCalendar();
		identity.nobleCondition = "nobleCondition";
		identity.duplicate = "duplicate";
		identity.gender = Gender.MALE;

		DTOMapper dtoMapper = new DTOMapper();

		// operate
		IdentityDTO result = dtoMapper.map(identity, IdentityDTO.class);

		// verify
		assertNotNull(result);
		assertEquals("hello-world", result.firstName);
		assertEquals("test-name", result.name);
		assertEquals("card-number", result.cardNumber);
		assertEquals("chip-number", result.chipNumber);
		assertEquals(identity.dateOfBirth, result.dateOfBirth);
		assertEquals("place-of-birth", result.placeOfBirth);
		assertEquals("nationality", result.nationality);
		assertEquals("middle-name", result.middleName);
		assertEquals("national-number", result.nationalNumber);
		assertEquals("cardDeliveryMunicipality",
				result.cardDeliveryMunicipality);
		assertEquals(identity.cardValidityDateBegin,
				result.cardValidityDateBegin);
		assertEquals(identity.cardValidityDateEnd, result.cardValidityDateEnd);
		assertEquals("nobleCondition", result.nobleCondition);
		assertEquals("duplicate", result.duplicate);
		assertTrue(result.male);
		assertFalse(result.female);
	}

	@Test
	public void testMapFemaleIdentity() throws Exception {
		// setup
		Identity identity = new Identity();
		identity.gender = Gender.FEMALE;

		DTOMapper dtoMapper = new DTOMapper();

		// operate
		IdentityDTO result = dtoMapper.map(identity, IdentityDTO.class);

		// verify
		assertNotNull(result);
		assertFalse(result.male);
		assertTrue(result.female);
	}

	@Test
	public void testMapNull() throws Exception {
		// setup
		DTOMapper dtoMapper = new DTOMapper();

		// operate
		IdentityDTO result = dtoMapper.map(null, IdentityDTO.class);

		// verify
		assertNull(result);
	}

	@Test
	public void testMapAddress() throws Exception {
		// setup
		Address address = new Address();
		address.streetAndNumber = "street 12345";
		address.zip = "1234";
		address.municipality = "city";

		DTOMapper dtoMapper = new DTOMapper();

		// operate
		AddressDTO result = dtoMapper.map(address, AddressDTO.class);

		// verify
		assertNotNull(result);
		assertEquals("street 12345", result.streetAndNumber);
		assertEquals("1234", result.zip);
		assertEquals("city", result.city);
	}
}
