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
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "beta_tests")
public class TestResultEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	private int id;

	private String test;

	private String result;

	private Calendar created;

	public TestResultEntity() {
		super();
	}

	public TestResultEntity(String test, String result,
			SessionContextEntity sessionContext) {
		this.test = test;
		this.result = result;
		this.sessionContext = sessionContext;
		this.created = Calendar.getInstance();
	}

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	public int getId() {
		return this.id;
	}

	public void setId(int id) {
		this.id = id;
	}

	@Column(nullable = false)
	public String getTest() {
		return this.test;
	}

	public void setTest(String test) {
		this.test = test;
	}

	@Lob
	@Column(length = 1024 * 10, nullable = false)
	public String getResult() {
		return this.result;
	}

	public void setResult(String result) {
		this.result = result;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
	public Calendar getCreated() {
		return this.created;
	}

	public void setCreated(Calendar created) {
		this.created = created;
	}

	private SessionContextEntity sessionContext;

	@ManyToOne(optional = false)
	public SessionContextEntity getSessionContext() {
		return this.sessionContext;
	}

	public void setSessionContext(SessionContextEntity sessionContext) {
		this.sessionContext = sessionContext;
	}
}
