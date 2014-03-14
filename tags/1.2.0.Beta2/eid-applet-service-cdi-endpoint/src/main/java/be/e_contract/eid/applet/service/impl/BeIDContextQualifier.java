/*
 * eID Applet Project.
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

package be.e_contract.eid.applet.service.impl;

import javax.enterprise.util.AnnotationLiteral;
import javax.servlet.http.HttpServletRequest;

import be.fedict.eid.applet.service.cdi.BeIDContext;

public class BeIDContextQualifier extends AnnotationLiteral<BeIDContext>
		implements BeIDContext {

	private static final long serialVersionUID = 1L;

	private String context;

	public BeIDContextQualifier(HttpServletRequest request) {
		String context = request.getServletPath();
		this.context = context;
	}

	public String getContext() {
		return this.context;
	}

	@Override
	public String value() {
		return this.context;
	}
}
