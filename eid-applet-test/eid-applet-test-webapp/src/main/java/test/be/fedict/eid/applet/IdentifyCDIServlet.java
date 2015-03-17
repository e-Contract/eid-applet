/*
 * eID Applet Project.
 * Copyright (C) 2014-2015 e-Contract.be BVBA.
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

package test.be.fedict.eid.applet;

import javax.servlet.annotation.WebServlet;

import be.e_contract.eid.applet.service.AppletServiceCDIServlet;

@WebServlet(IdentifyCDIServlet.CONTEXT)
public class IdentifyCDIServlet extends AppletServiceCDIServlet {

	private static final long serialVersionUID = 1L;

	public static final String CONTEXT = "/applet-service-cdi";
}
