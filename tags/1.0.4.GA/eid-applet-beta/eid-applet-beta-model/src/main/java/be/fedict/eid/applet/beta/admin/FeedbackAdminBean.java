/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.datamodel.DataModelSelection;
import org.jboss.seam.log.Log;

import be.fedict.eid.applet.beta.FeedbackEntity;
import be.fedict.eid.applet.beta.TestResultEntity;

@Stateful
@Scope(ScopeType.SESSION)
@Name("feedbackAdmin")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/FeedbackAdminBean")
public class FeedbackAdminBean implements FeedbackAdmin {

	@SuppressWarnings("unused")
	@DataModel(scope = ScopeType.PAGE)
	private List<FeedbackEntity> feedbackList;

	@DataModelSelection
	@Out(required = false)
	private FeedbackEntity selectedFeedback;

	@SuppressWarnings("unused")
	@Out(required = false)
	private List<TestResultEntity> testResults;

	@Logger
	private Log log;

	@PersistenceContext
	private EntityManager entityManager;

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}

	@SuppressWarnings("unchecked")
	@Factory("feedbackList")
	public void listMessages() {
		this.log.debug("list messages");
		this.feedbackList = this.entityManager.createQuery(
				"FROM FeedbackEntity AS f ORDER BY f.id DESC").getResultList();
	}

	@SuppressWarnings("unchecked")
	public String view() {
		this.log.debug("view: " + this.selectedFeedback.getId());
		Query query = this.entityManager
				.createQuery("FROM TestResultEntity AS tr WHERE tr.sessionContext = :sessionContext");
		query.setParameter("sessionContext", this.selectedFeedback
				.getSessionContext());
		this.testResults = query.getResultList();
		return "view";
	}

	public String delete() {
		this.log.debug("delete #0", this.selectedFeedback.getId());
		Query query = this.entityManager
				.createQuery("FROM FeedbackEntity AS f WHERE f.id = :id");
		query.setParameter("id", this.selectedFeedback.getId());
		FeedbackEntity attachedFeedbackEntity = (FeedbackEntity) query
				.getSingleResult();
		this.entityManager.remove(attachedFeedbackEntity);
		this.selectedFeedback = null;
		this.feedbackList = null; // force refresh
		return "success";
	}
}
