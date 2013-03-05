/*
 * eID Applet Project.
 * Copyright (C) 2013 FedICT.
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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JDialog;
import javax.swing.Timer;

public class KillDialogActionListener implements ActionListener {

	private final JDialog dialog;
	
	private final Timer timer;
	
	public KillDialogActionListener(Timer timer, JDialog dialog) {
		this.timer = timer;
		this.dialog = dialog;
	}
	
	public void actionPerformed(ActionEvent event) {
		if (this.dialog.isVisible()) {
			this.dialog.dispose();
			this.timer.stop();
		}
	}
}
