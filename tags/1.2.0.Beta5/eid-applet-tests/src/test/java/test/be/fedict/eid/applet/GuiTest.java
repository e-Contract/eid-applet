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

package test.be.fedict.eid.applet;

import javax.swing.JFrame;

import org.fest.swing.applet.AppletViewer;
import org.fest.swing.fixture.FrameFixture;
import org.fest.swing.launcher.AppletLauncher;
import org.junit.Test;

import be.fedict.eid.applet.Applet;

public class GuiTest {

	@Test
	public void testAppletGUI() throws Exception {
		AppletViewer appletViewer = AppletLauncher.applet(new Applet()).start();
		FrameFixture applet = new FrameFixture(appletViewer);
		applet.show();
	}

	@Test
	public void testAppletInJFrame() throws Exception {
		JFrame frame = new JFrame();
		final Applet applet = new Applet();
		frame.getContentPane().add(applet);
		frame.setVisible(true);
		applet.init();
	}
}
