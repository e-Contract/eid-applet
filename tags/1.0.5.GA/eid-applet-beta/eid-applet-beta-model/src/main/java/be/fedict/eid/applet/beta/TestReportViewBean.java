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

package be.fedict.eid.applet.beta;

import java.util.List;

import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.log.Log;

@Stateful
@Name("testReportView")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/TestReportViewBean")
public class TestReportViewBean implements TestReportView {

	@Logger
	private Log log;

	@PersistenceContext
	private EntityManager entityManager;

	@DataModel
	private List<TestReportEntity> testReport;

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}

	@Factory("testReport")
	public void createTestReport() {
		Query query = this.entityManager
				.createNamedQuery(TestReportEntity.QUERY_TEST_REPORT);
		this.testReport = query.getResultList();
	}
}
