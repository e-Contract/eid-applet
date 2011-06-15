/*
 * eID Applet Project.
 * Copyright (C) 2008-2009 FedICT.
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

import static be.fedict.eid.applet.beta.TestReportEntity.QUERY_TEST_REPORT;

import java.io.Serializable;
import java.util.Calendar;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "beta_test_report")
@NamedQueries({ @NamedQuery(name = QUERY_TEST_REPORT, query = "SELECT testReport FROM TestReportEntity AS testReport"
		+ " ORDER BY test, osName, osVersion,  osArch, javaVersion, userAgent") })
public class TestReportEntity implements Serializable {

	public static final String QUERY_TEST_REPORT = "query.test.report";

	private static final long serialVersionUID = 1L;

	private int id;

	private TestReportType test;

	private TestReportResult result;

	private Calendar created;

	private String javaVersion;
	private String javaVendor;
	private String osName;
	private String osArch;
	private String osVersion;
	private String userAgent;
	private String navigatorAppName;
	private String navigatorAppVersion;
	private String navigatorUserAgent;

	public TestReportEntity() {
		super();
	}

	public TestReportEntity(String javaVersion, String javaVendor,
			String osName, String osArch, String osVersion, String userAgent,
			String navigatorAppName, String navigatorAppVersion,
			String navigatorUserAgent) {
		this.result = TestReportResult.UNFINISHED;
		this.created = Calendar.getInstance();
		this.javaVersion = javaVersion;
		this.javaVendor = javaVendor;
		this.osName = osName;
		this.osArch = osArch;
		this.osVersion = osVersion;
		this.userAgent = userAgent;
		this.navigatorAppName = navigatorAppName;
		this.navigatorAppVersion = navigatorAppVersion;
		this.navigatorUserAgent = navigatorUserAgent;
	}

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	public int getId() {
		return this.id;
	}

	public void setId(int id) {
		this.id = id;
	}

	@Enumerated(EnumType.STRING)
	public TestReportType getTest() {
		return this.test;
	}

	public void setTest(TestReportType test) {
		this.test = test;
	}

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	public TestReportResult getResult() {
		return this.result;
	}

	public void setResult(TestReportResult result) {
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

	public String getJavaVersion() {
		return this.javaVersion;
	}

	public void setJavaVersion(String javaVersion) {
		this.javaVersion = javaVersion;
	}

	public String getJavaVendor() {
		return this.javaVendor;
	}

	public void setJavaVendor(String javaVendor) {
		this.javaVendor = javaVendor;
	}

	public String getOsName() {
		return this.osName;
	}

	public void setOsName(String osName) {
		this.osName = osName;
	}

	public String getOsArch() {
		return this.osArch;
	}

	public void setOsArch(String osArch) {
		this.osArch = osArch;
	}

	public String getOsVersion() {
		return this.osVersion;
	}

	public void setOsVersion(String osVersion) {
		this.osVersion = osVersion;
	}

	public String getUserAgent() {
		return this.userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public String getNavigatorAppName() {
		return this.navigatorAppName;
	}

	public void setNavigatorAppName(String navigatorAppName) {
		this.navigatorAppName = navigatorAppName;
	}

	public String getNavigatorAppVersion() {
		return this.navigatorAppVersion;
	}

	public void setNavigatorAppVersion(String navigatorAppVersion) {
		this.navigatorAppVersion = navigatorAppVersion;
	}

	@Column(length = 512)
	public String getNavigatorUserAgent() {
		return this.navigatorUserAgent;
	}

	public void setNavigatorUserAgent(String navigatorUserAgent) {
		this.navigatorUserAgent = navigatorUserAgent;
	}
}
