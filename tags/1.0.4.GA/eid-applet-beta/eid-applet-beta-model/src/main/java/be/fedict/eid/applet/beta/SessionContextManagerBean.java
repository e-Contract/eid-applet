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

import java.util.List;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

@Stateless
public class SessionContextManagerBean implements SessionContextManager {

	private static final Log LOG = LogFactory
			.getLog(SessionContextManagerBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	@SuppressWarnings("unchecked")
	public int getSessionContextId(String httpSessionId) {
		LOG.debug("get context Id for HTTP session Id: " + httpSessionId);

		Query query = this.entityManager
				.createQuery("FROM SessionContextEntity AS sc WHERE sc.httpSessionId = :httpSessionId");
		query.setParameter("httpSessionId", httpSessionId);
		List<SessionContextEntity> sessionContextList = query.getResultList();
		if (sessionContextList.isEmpty()) {
			HttpServletRequest httpServletRequest;
			try {
				httpServletRequest = (HttpServletRequest) PolicyContext
						.getContext("javax.servlet.http.HttpServletRequest");
			} catch (PolicyContextException e) {
				throw new RuntimeException("JACC error: " + e.getMessage());
			}
			String userAgent = httpServletRequest.getHeader("user-agent");
			LOG.debug("user agent: " + userAgent);
			SessionContextEntity sessionContextEntity = new SessionContextEntity(
					httpSessionId, userAgent);
			this.entityManager.persist(sessionContextEntity);
			int contextId = sessionContextEntity.getContextId();
			LOG.debug("new context Id: " + contextId);
			return contextId;
		}
		/*
		 * An existing HTTP session will come from the same user agent.
		 */
		SessionContextEntity sessionContextEntity = sessionContextList.get(0);
		int contextId = sessionContextEntity.getContextId();
		LOG.debug("existing context Id: " + contextId);
		return contextId;
	}

	public void deactivateSessionContext(String httpSessionId) {
		LOG.debug("deactivate context for HTTP session: " + httpSessionId);
		SessionContextEntity sessionContextEntity = getSessionContextEntity(httpSessionId);
		sessionContextEntity.setActive(false);
		LOG
				.debug("context deactivated: "
						+ sessionContextEntity.getContextId());
	}

	private SessionContextEntity getSessionContextEntity(String httpSessionId) {
		Query query = this.entityManager
				.createQuery("FROM SessionContextEntity AS sc WHERE sc.httpSessionId = :httpSessionId");
		query.setParameter("httpSessionId", httpSessionId);
		SessionContextEntity sessionContextEntity = (SessionContextEntity) query
				.getSingleResult();
		return sessionContextEntity;
	}

	public int getSessionContextId() {
		SessionContextEntity sessionContextEntity = getSessionContext();
		int contextId = sessionContextEntity.getContextId();
		return contextId;
	}

	public SessionContextEntity getSessionContext() {
		HttpServletRequest httpServletRequest;
		try {
			httpServletRequest = (HttpServletRequest) PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");
		} catch (PolicyContextException e) {
			throw new RuntimeException("JACC error: " + e.getMessage());
		}
		HttpSession httpSession = httpServletRequest.getSession();
		String httpSessionId = httpSession.getId();
		SessionContextEntity sessionContextEntity = getSessionContextEntity(httpSessionId);
		return sessionContextEntity;
	}
}
