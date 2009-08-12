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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Arrays;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import be.fedict.eid.applet.Messages.MESSAGE_ID;

/**
 * Holds the implementation of some eID related dialogs.
 * 
 * @author fcorneli
 * 
 */
public class Dialogs {

	/*
	 * TODO: should somehow also be declared in the View interface.
	 */

	private final View view;

	private final Messages messages;

	public Dialogs(View view, Messages messages) {
		this.view = view;
		this.messages = messages;
	}

	public void getPuks(int retriesLeft, char[] puk1, char[] puk2) {
		Box mainPanel = Box.createVerticalBox();

		if (-1 != retriesLeft) {
			Box retriesPanel = Box.createHorizontalBox();
			JLabel retriesLabel = new JLabel(this.messages
					.getMessage(MESSAGE_ID.RETRIES_LEFT)
					+ ": " + retriesLeft);
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
			JLabel retriesLabel = new JLabel(this.messages
					.getMessage(MESSAGE_ID.RETRIES_LEFT)
					+ ": " + retriesLeft);
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

	private JFrame pinPadFrame;

	public void showPINPadFrame(int retriesLeft) {
		if (null != this.pinPadFrame) {
			disposePINPadFrame();
		}
		this.pinPadFrame = new JFrame("PIN");
		JPanel panel = new JPanel() {
			private static final long serialVersionUID = 1L;

			@Override
			public Insets getInsets() {
				return new Insets(10, 30, 10, 30);
			}
		};
		BoxLayout boxLayout = new BoxLayout(panel, BoxLayout.PAGE_AXIS);
		panel.setLayout(boxLayout);

		if (-1 != retriesLeft) {
			JLabel retriesLabel = new JLabel(this.messages
					.getMessage(MESSAGE_ID.RETRIES_LEFT)
					+ ": " + retriesLeft);
			retriesLabel.setForeground(Color.RED);
			panel.add(retriesLabel);
		}
		panel.add(new JLabel(this.messages.getMessage(MESSAGE_ID.PIN_PAD)));
		this.pinPadFrame.getContentPane().add(panel);
		this.pinPadFrame.pack();
		this.pinPadFrame.setLocationRelativeTo(this.view.getParentComponent());
		this.pinPadFrame.setVisible(true);
	}

	public void disposePINPadFrame() {
		if (null != this.pinPadFrame) {
			this.pinPadFrame.dispose();
			this.pinPadFrame = null;
		}
	}

	public char[] getPin(int retriesLeft) {
		// main panel
		JPanel mainPanel = new JPanel() {
			private static final long serialVersionUID = 1L;

			private static final int BORDER_SIZE = 20;

			@Override
			public Insets getInsets() {
				return new Insets(BORDER_SIZE, BORDER_SIZE, BORDER_SIZE,
						BORDER_SIZE);
			}
		};
		BoxLayout boxLayout = new BoxLayout(mainPanel, BoxLayout.PAGE_AXIS);
		mainPanel.setLayout(boxLayout);

		if (-1 != retriesLeft) {
			Box retriesPanel = Box.createHorizontalBox();
			JLabel retriesLabel = new JLabel(this.messages
					.getMessage(MESSAGE_ID.RETRIES_LEFT)
					+ ": " + retriesLeft);
			retriesLabel.setForeground(Color.RED);
			retriesPanel.add(retriesLabel);
			retriesPanel.add(Box.createHorizontalGlue());
			mainPanel.add(retriesPanel);
			mainPanel.add(Box.createVerticalStrut(5));
		}

		Box passwordPanel = Box.createHorizontalBox();
		JLabel promptLabel = new JLabel("eID PIN:");
		passwordPanel.add(promptLabel);
		passwordPanel.add(Box.createHorizontalStrut(5));
		final JPasswordField passwordField = new JPasswordField(8);
		passwordPanel.add(passwordField);
		mainPanel.add(passwordPanel);

		// button panel
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT)) {
			private static final long serialVersionUID = 1L;

			@Override
			public Insets getInsets() {
				return new Insets(0, 0, 5, 5);
			}
		};
		final JButton okButton = new JButton("OK");
		okButton.setEnabled(false);
		buttonPanel.add(okButton);
		JButton cancelButton = new JButton("Cancel");
		buttonPanel.add(cancelButton);

		// dialog box
		final JDialog dialog = new JDialog((Frame) null, "eID PIN?", true);
		dialog.setLayout(new BorderLayout());
		dialog.getContentPane().add(mainPanel, BorderLayout.CENTER);
		dialog.getContentPane().add(buttonPanel, BorderLayout.SOUTH);

		final DialogResult dialogResult = new DialogResult();

		okButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				dialogResult.result = DialogResult.Result.OK;
				dialog.dispose();
			}
		});
		cancelButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				dialogResult.result = DialogResult.Result.CANCEL;
				dialog.dispose();
			}
		});
		passwordField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				if (passwordField.getPassword().length == 4) {
					dialogResult.result = DialogResult.Result.OK;
					dialog.dispose();
				}
			}
		});
		passwordField.addKeyListener(new KeyListener() {

			public void keyPressed(KeyEvent e) {
			}

			public void keyReleased(KeyEvent e) {
				if (passwordField.getPassword().length == 4) {
					okButton.setEnabled(true);
				} else {
					okButton.setEnabled(false);
				}
			}

			public void keyTyped(KeyEvent e) {
			}
		});

		dialog.pack();
		dialog.setLocationRelativeTo(this.view.getParentComponent());
		dialog.setVisible(true);
		// setVisible will wait until some button or so has been pressed

		if (dialogResult.result == DialogResult.Result.OK) {
			char[] pin = passwordField.getPassword();
			return pin;
		}
		throw new RuntimeException("operation canceled.");
	}

	private static class DialogResult {
		enum Result {
			OK, CANCEL
		};

		public Result result = null;
	}

	public void showPinBlockedDialog() {
		JOptionPane.showMessageDialog(this.view.getParentComponent(),
				this.messages.getMessage(MESSAGE_ID.PIN_BLOCKED),
				"eID card blocked", JOptionPane.ERROR_MESSAGE);
	}

	public void showPinChanged() {
		JOptionPane.showMessageDialog(this.view.getParentComponent(),
				this.messages.getMessage(MESSAGE_ID.PIN_CHANGED),
				"eID PIN change", JOptionPane.INFORMATION_MESSAGE);
	}

	public void showPinUnblocked() {
		JOptionPane.showMessageDialog(this.view.getParentComponent(),
				this.messages.getMessage(MESSAGE_ID.PIN_UNBLOCKED),
				"eID PIN unblock", JOptionPane.INFORMATION_MESSAGE);
	}
}
