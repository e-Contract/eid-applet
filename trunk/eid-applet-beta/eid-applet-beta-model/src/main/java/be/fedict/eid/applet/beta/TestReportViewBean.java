/*
 * eID Applet Project.
 * Copyright (C) 2009-2014 e-Contract.be BVBA.
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

import javax.inject.Named;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

@Named("betaReport")
public class TestReportViewBean {

	@PersistenceContext
	private EntityManager entityManager;

	public List<TestReportEntity> getReport() {
		Query query = this.entityManager
				.createNamedQuery(TestReportEntity.QUERY_TEST_REPORT);
		return query.getResultList();
	}
}
