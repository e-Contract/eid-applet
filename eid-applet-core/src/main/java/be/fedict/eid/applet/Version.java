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

package be.fedict.eid.applet;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * eID Applet Version class.
 * 
 * @author Frank Cornelis
 * 
 */
public class Version {

	public static final String VERSION_PROPERTY = "be.fedict.eid.applet.version";

	private String version;

	public String getVersion() {
		loadApplicationProperties();
		return this.version;
	}

	private void loadApplicationProperties() {
		if (null != this.version) {
			/*
			 * Only load once.
			 */
			return;
		}
		ClassLoader classLoader = Thread.currentThread()
				.getContextClassLoader();
		InputStream applicationPropertiesInputStream = classLoader
				.getResourceAsStream("be/fedict/eid/applet/application.properties");
		if (null == applicationPropertiesInputStream) {
			this.version = "application properties resource not found";
			return;
		}
		Properties properties = new Properties();
		try {
			properties.load(applicationPropertiesInputStream);
		} catch (IOException e) {
			this.version = "error loading application properties";
			return;
		}
		this.version = (String) properties.get(VERSION_PROPERTY);
	}
}
