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

package be.fedict.eid.applet.service;

import java.io.Serializable;

import be.fedict.eid.applet.service.dto.Mapping;
import be.fedict.eid.applet.service.dto.MapsTo;
import be.fedict.eid.applet.service.impl.tlv.TlvField;
import be.fedict.eid.applet.service.spi.AddressDTO;

/**
 * Holds all the fields within the eID address file. The nationality can be
 * found in the eID identity file.
 * 
 * @author Frank Cornelis
 * @see Identity
 * 
 */
public class Address implements Serializable {

	/*
	 * We implement serializable to allow this class to be used in distributed
	 * containers as defined in the Servlet v2.4 specification.
	 */

	private static final long serialVersionUID = 1L;

	@TlvField(1)
	@Mapping(@MapsTo(AddressDTO.class))
	public String streetAndNumber;

	@TlvField(2)
	@Mapping(@MapsTo(AddressDTO.class))
	public String zip;

	@TlvField(3)
	@Mapping(@MapsTo(value = AddressDTO.class, field = "city"))
	public String municipality;

	/*
	 * We're also providing getters to make this class more useful within web
	 * frameworks like JBoss Seam.
	 */

	public String getStreetAndNumber() {
		return this.streetAndNumber;
	}

	public String getZip() {
		return this.zip;
	}

	public String getMunicipality() {
		return this.municipality;
	}
}
