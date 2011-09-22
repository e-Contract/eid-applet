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

package be.fedict.eid.applet.beta;

import java.util.Calendar;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;

@Stateless
@Name("feedback")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/FeedbackBean")
public class FeedbackBean implements Feedback {

	@Logger
	private Log log;

	@In
	private FeedbackEntity feedbackEntry;

	@PersistenceContext
	private EntityManager entityManager;

	@EJB
	private SessionContextManager sessionContextManager;

	public String save() {
		Calendar now = Calendar.getInstance();
		this.log.debug("save feedback: " + now.getTime());
		this.feedbackEntry.setCreated(now);
		SessionContextEntity sessionContext = this.sessionContextManager
				.getSessionContext();
		this.feedbackEntry.setSessionContext(sessionContext);
		this.entityManager.persist(this.feedbackEntry);
		return "success";
	}
}
