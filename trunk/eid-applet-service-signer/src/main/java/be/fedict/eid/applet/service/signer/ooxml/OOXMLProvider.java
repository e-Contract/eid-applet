/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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

package be.fedict.eid.applet.service.signer.ooxml;

import java.security.Provider;

public class OOXMLProvider extends Provider {

	public OOXMLProvider() {
		super("OOXMLProvider", 1.0, "OOXML Security Provider");
		put("TransformService." + RelationshipTransformService.TRANSFORM_URI,
				RelationshipTransformService.class.getName());
		put("TransformService." + RelationshipTransformService.TRANSFORM_URI
				+ " MechanismType", "DOM");
	}

	private static final long serialVersionUID = 1L;

}
