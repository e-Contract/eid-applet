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

package be.fedict.eid.applet.beta.service;

import java.io.Serializable;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

public class SimpleGroup implements Group, Serializable {

	private static final long serialVersionUID = 1L;

	private final String name;

	private final Set<Principal> members;

	public SimpleGroup(String name) {
		this.name = name;
		this.members = new HashSet<Principal>();
	}

	public String getName() {
		return this.name;
	}

	public boolean addMember(Principal user) {
		this.members.add(user);
		return true;
	}

	public boolean isMember(Principal member) {
		return this.members.contains(member);
	}

	public Enumeration<? extends Principal> members() {
		return Collections.enumeration(this.members);
	}

	public boolean removeMember(Principal user) {
		return this.members.remove(user);
	}
}
