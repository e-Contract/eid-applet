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

package be.fedict.eid.applet.service.spi;

import java.io.Serializable;
import java.util.GregorianCalendar;

/**
 * Identity Data Transfer Object.
 * 
 * @author Frank Cornelis
 * 
 */
public class IdentityDTO implements Serializable {

	/*
	 * We implement serializable to allow this class to be used in distributed
	 * containers as defined in the Servlet v2.4 specification.
	 */
	private static final long serialVersionUID = 1L;

	public String cardNumber;

	public String chipNumber;

	public GregorianCalendar cardValidityDateBegin;

	public GregorianCalendar cardValidityDateEnd;

	public String cardDeliveryMunicipality;

	public String nationalNumber;

	public String name;

	public String firstName;

	public String middleName;

	public String nationality;

	public String placeOfBirth;

	public GregorianCalendar dateOfBirth;

	public boolean male;

	public boolean female;

	public String nobleCondition;

	public String duplicate;
}
