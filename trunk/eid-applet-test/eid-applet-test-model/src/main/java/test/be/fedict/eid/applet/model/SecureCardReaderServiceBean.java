/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package test.be.fedict.eid.applet.model;

import java.util.Calendar;

import javax.ejb.EJB;
import javax.ejb.Stateless;

@Stateless
@EJB(name = "java:global/test/SecureCardReaderServiceBean", beanInterface = SecureCardReaderService.class)
public class SecureCardReaderServiceBean implements SecureCardReaderService {

	public String getTransactionMessage() {
		Calendar calendar = Calendar.getInstance();
		String message = "Test Application @ "
				+ calendar.get(Calendar.DAY_OF_MONTH) + "/"
				+ (calendar.get(Calendar.MONTH) + 1) + "/"
				+ calendar.get(Calendar.YEAR) + " "
				+ calendar.get(Calendar.HOUR_OF_DAY) + ":"
				+ calendar.get(Calendar.MINUTE) + ":"
				+ calendar.get(Calendar.SECOND);
		return message;
	}
}
