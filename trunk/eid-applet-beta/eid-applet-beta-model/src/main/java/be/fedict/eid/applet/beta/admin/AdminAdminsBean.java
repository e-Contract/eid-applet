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

package be.fedict.eid.applet.beta.admin;

import java.util.List;

import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.datamodel.DataModelSelection;
import org.jboss.seam.log.Log;

@Stateful
@Scope(ScopeType.SESSION)
@Name("adminAdmins")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/AdminAdminsBean")
public class AdminAdminsBean implements AdminAdmins {

	@Logger
	private Log log;

	@PersistenceContext
	private EntityManager entityManager;

	@DataModel(scope = ScopeType.PAGE)
	private List<AdministratorEntity> adminList;

	@DataModelSelection
	private AdministratorEntity selectedAdmin;

	@In
	private FacesContext facesContext;

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}

	@SuppressWarnings("unchecked")
	@Factory("adminList")
	public void listAdmins() {
		this.log.debug("list admins");
		this.adminList = this.entityManager.createQuery(
				"FROM AdministratorEntity").getResultList();
	}

	public String delete() {
		if (this.adminList.size() <= 1) {
			this.facesContext.addMessage(null, new FacesMessage(
					"need at least one admin to login"));
			return null;
		}
		AdministratorEntity toBeRemovedAdmin = this.entityManager.find(
				AdministratorEntity.class, this.selectedAdmin.getId());
		this.entityManager.remove(toBeRemovedAdmin);
		listAdmins();
		return "view";
	}
}
