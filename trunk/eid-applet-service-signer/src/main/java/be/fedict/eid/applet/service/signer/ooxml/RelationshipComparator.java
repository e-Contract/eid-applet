/*
 * eID Applet Project.
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

import java.util.Comparator;

import org.w3c.dom.Element;

/**
 * Comparator for Relationship DOM elements.
 * 
 * @author Frank Cornelis
 * 
 */
public class RelationshipComparator implements Comparator<Element> {

	public int compare(Element element1, Element element2) {
		String id1 = element1.getAttribute("Id");
		String id2 = element2.getAttribute("Id");
		return id1.compareTo(id2);
	}
}
