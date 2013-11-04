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

import java.io.Serializable;
import java.util.Calendar;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.hibernate.annotations.Index;

@Entity
@Table(name = "beta_sessions")
public class SessionContextEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	private int contextId;

	private String httpSessionId;

	private String userAgent;

	private Calendar created;

	private boolean active;

	public SessionContextEntity() {
		super();
	}

	public SessionContextEntity(String httpSessionId, String userAgent) {
		this.httpSessionId = httpSessionId;
		this.userAgent = userAgent;
		this.created = Calendar.getInstance();
		this.active = true;
	}

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	public int getContextId() {
		return this.contextId;
	}

	public void setContextId(int contextId) {
		this.contextId = contextId;
	}

	@Column(unique = true, nullable = false)
	@Index(name = "HttpSessionIdIndex")
	public String getHttpSessionId() {
		return this.httpSessionId;
	}

	public void setHttpSessionId(String httpSessionId) {
		this.httpSessionId = httpSessionId;
	}

	@Column(nullable = false)
	public String getUserAgent() {
		return this.userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getCreated() {
		return this.created;
	}

	public void setCreated(Calendar created) {
		this.created = created;
	}

	public boolean isActive() {
		return this.active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}
}
