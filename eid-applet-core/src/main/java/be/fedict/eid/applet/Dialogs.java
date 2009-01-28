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

package be.fedict.eid.applet;

import java.awt.Component;
import java.util.Arrays;

import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

/**
 * Holds the implementation of some eID related dialogs.
 * 
 * @author fcorneli
 * 
 */
public class Dialogs {

	private final View view;

	public Dialogs(View view) {
		this.view = view;
	}

	public void getPuks(int retriesLeft, char[] puk1, char[] puk2) {
		Box mainPanel = Box.createVerticalBox();

		if (-1 != retriesLeft) {
			Box retriesPanel = Box.createHorizontalBox();
			JLabel retriesLabel = new JLabel("Retries left: " + retriesLeft);
			retriesPanel.add(retriesLabel);
			retriesPanel.add(Box.createHorizontalGlue());
			mainPanel.add(retriesPanel);
			mainPanel.add(Box.createVerticalStrut(5));
		}

		JPasswordField puk1Field = new JPasswordField(8);
		{
			Box puk1Panel = Box.createHorizontalBox();
			JLabel puk1Label = new JLabel("eID PUK1:");
			puk1Panel.add(puk1Label);
			puk1Panel.add(Box.createHorizontalStrut(5));
			puk1Panel.add(puk1Field);
			mainPanel.add(puk1Panel);
		}

		JPasswordField puk2Field = new JPasswordField(8);
		{
			Box puk2Panel = Box.createHorizontalBox();
			JLabel puk2Label = new JLabel("eID PUK2:");
			puk2Panel.add(puk2Label);
			puk2Panel.add(Box.createHorizontalStrut(5));
			puk2Panel.add(puk2Field);
			mainPanel.add(puk2Panel);
		}

		Component parentComponent = this.view.getParentComponent();
		int result = JOptionPane.showOptionDialog(parentComponent, mainPanel,
				"eID PIN unblock", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, null, null);
		if (result != JOptionPane.OK_OPTION) {
			throw new RuntimeException("operation canceled.");
		}
		System.arraycopy(puk1Field.getPassword(), 0, puk1, 0, 6);
		System.arraycopy(puk2Field.getPassword(), 0, puk2, 0, 6);
	}

	public void getPins(int retriesLeft, char[] oldPin, char[] newPin) {
		Box mainPanel = Box.createVerticalBox();

		if (-1 != retriesLeft) {
			Box retriesPanel = Box.createHorizontalBox();
			JLabel retriesLabel = new JLabel("Retries left: " + retriesLeft);
			retriesPanel.add(retriesLabel);
			retriesPanel.add(Box.createHorizontalGlue());
			mainPanel.add(retriesPanel);
			mainPanel.add(Box.createVerticalStrut(5));
		}

		JPasswordField oldPinField = new JPasswordField(8);
		{
			Box oldPinPanel = Box.createHorizontalBox();
			JLabel oldPinLabel = new JLabel("Current eID PIN:");
			oldPinPanel.add(oldPinLabel);
			oldPinPanel.add(Box.createHorizontalStrut(5));
			oldPinPanel.add(oldPinField);
			mainPanel.add(oldPinPanel);
		}

		JPasswordField newPinField = new JPasswordField(8);
		{
			Box newPinPanel = Box.createHorizontalBox();
			JLabel newPinLabel = new JLabel("New eID PIN:");
			newPinPanel.add(newPinLabel);
			newPinPanel.add(Box.createHorizontalStrut(5));
			newPinPanel.add(newPinField);
			mainPanel.add(newPinPanel);
		}

		JPasswordField new2PinField = new JPasswordField(8);
		{
			Box new2PinPanel = Box.createHorizontalBox();
			JLabel new2PinLabel = new JLabel("New eID PIN:");
			new2PinPanel.add(new2PinLabel);
			new2PinPanel.add(Box.createHorizontalStrut(5));
			new2PinPanel.add(new2PinField);
			mainPanel.add(new2PinPanel);
		}

		Component parentComponent = this.view.getParentComponent();
		int result = JOptionPane.showOptionDialog(parentComponent, mainPanel,
				"Change eID PIN", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, null, null);
		if (result != JOptionPane.OK_OPTION) {
			throw new RuntimeException("operation canceled.");
		}
		if (false == Arrays.equals(newPinField.getPassword(), new2PinField
				.getPassword())) {
			throw new RuntimeException("new PINs not equal");
		}
		System.arraycopy(oldPinField.getPassword(), 0, oldPin, 0, 4);
		System.arraycopy(newPinField.getPassword(), 0, newPin, 0, 4);
	}

	public char[] getPin() {
		return getPin(-1);
	}

	public char[] getPin(int retriesLeft) {
		Box mainPanel = Box.createVerticalBox();

		if (-1 != retriesLeft) {
			Box retriesPanel = Box.createHorizontalBox();
			JLabel retriesLabel = new JLabel("Retries left: " + retriesLeft);
			retriesPanel.add(retriesLabel);
			retriesPanel.add(Box.createHorizontalGlue());
			mainPanel.add(retriesPanel);
			mainPanel.add(Box.createVerticalStrut(5));
		}

		Box passwordPanel = Box.createHorizontalBox();
		JLabel promptLabel = new JLabel("eID PIN:");
		passwordPanel.add(promptLabel);
		passwordPanel.add(Box.createHorizontalStrut(5));
		JPasswordField passwordField = new JPasswordField(8);
		passwordPanel.add(passwordField);
		mainPanel.add(passwordPanel);

		Component parentComponent = this.view.getParentComponent();
		int result = JOptionPane.showOptionDialog(parentComponent, mainPanel,
				"eID PIN?", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, null, null);
		if (result == JOptionPane.OK_OPTION) {
			char[] pin = passwordField.getPassword();
			return pin;
		}
		throw new RuntimeException("operation canceled.");
	}
}
