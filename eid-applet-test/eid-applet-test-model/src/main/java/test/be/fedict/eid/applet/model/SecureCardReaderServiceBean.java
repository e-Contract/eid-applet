/*
 * eID Applet Project.
 * Copyright (C) 2008-2012 FedICT.
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

import javax.ejb.Local;
import javax.ejb.Stateless;

import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.SecureCardReaderService;

@Stateless
@Local(SecureCardReaderService.class)
@LocalBinding(jndiBinding = "test/eid/applet/model/SecureCardReaderServiceBean")
public class SecureCardReaderServiceBean implements SecureCardReaderService {

	public String getMessage() {
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
