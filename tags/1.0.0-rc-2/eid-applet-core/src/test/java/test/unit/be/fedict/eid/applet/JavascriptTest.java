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

package test.unit.be.fedict.eid.applet;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;

import javax.swing.JApplet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.eid.applet.Applet;

/**
 * Javascript security test. We don't allow Javascript to access our eID Applet.
 * 
 * @author Frank Cornelis
 * 
 */
public class JavascriptTest {

	private static final Log LOG = LogFactory.getLog(JavascriptTest.class);

	@Test
	public void onlyJAppletMethodsAreAvailable() throws Exception {
		Class<Applet> appletClass = Applet.class;
		Method[] methods = appletClass.getMethods();
		for (Method method : methods) {
			if (false == method.getDeclaringClass().equals(appletClass)) {
				continue;
			}
			LOG.debug("applet method: " + method.getName());
			assertTrue(isJAppletMethod(method));
		}
	}

	private boolean isJAppletMethod(Method method) throws SecurityException,
			NoSuchMethodException {
		if (null == JApplet.class.getMethod(method.getName(), method
				.getParameterTypes())) {
			return false;
		}
		return true;
	}
}