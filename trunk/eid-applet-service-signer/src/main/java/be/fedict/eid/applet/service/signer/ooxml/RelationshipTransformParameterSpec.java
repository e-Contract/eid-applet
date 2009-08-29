/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2009 Frank Cornelis.
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

import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.dsig.spec.TransformParameterSpec;

/**
 * Relationship Transform parameter specification class.
 * 
 * @author fcorneli
 * 
 */
public class RelationshipTransformParameterSpec implements
		TransformParameterSpec {

	private final List<String> sourceIds;

	/**
	 * Main constructor.
	 */
	public RelationshipTransformParameterSpec() {
		this.sourceIds = new LinkedList<String>();
	}

	/**
	 * Adds a relationship reference for the given source identifier.
	 * 
	 * @param sourceId
	 */
	public void addRelationshipReference(String sourceId) {
		this.sourceIds.add(sourceId);
	}

	List<String> getSourceIds() {
		return this.sourceIds;
	}
}
