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

import java.awt.Component;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;

import javax.swing.Timer;

public class FocusDialogActionListener implements ActionListener {

	private final Component component;
	
	private final Timer timer;
	
	public FocusDialogActionListener(Timer timer, Component component) {
		this.timer = timer;
		this.component = component;
	}
	
	public void actionPerformed(ActionEvent event) {
		if (this.component.isVisible()) {
			EventQueue eventQueue = new EventQueue();
			eventQueue.postEvent(new FocusEvent(this.component, FocusEvent.FOCUS_GAINED));
			this.timer.stop();
		}
	}
}
