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
 * @author Frank Cornelis
 * 
 */
public class Dialogs {

	/*
	 * TODO: should somehow also be declared in the View interface.
	 */

	public static final int MIN_PIN_SIZE = 4;

	public static final int MAX_PIN_SIZE = 12;

	public static final int PUK_SIZE = 6;

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
			retriesLabel.setForeground(Color.RED);
			retriesPanel.add(retriesLabel);
			retriesPanel.add(Box.createHorizontalGlue());
			mainPanel.add(retriesPanel);
			mainPanel.add(Box.createVerticalStrut(5));
		}

		JPasswordField puk1Field = new JPasswordField(8);
		{
			Box puk1Panel = Box.createHorizontalBox();
			JLabel puk1Label = new JLabel("eID PUK1:");
			puk1Label.setLabelFor(puk1Field);
			puk1Panel.add(puk1Label);
			puk1Panel.add(Box.createHorizontalStrut(5));
			puk1Panel.add(puk1Field);
			mainPanel.add(puk1Panel);
		}

		mainPanel.add(Box.createVerticalStrut(5));

		JPasswordField puk2Field = new JPasswordField(8);
		{
			Box puk2Panel = Box.createHorizontalBox();
			JLabel puk2Label = new JLabel("eID PUK2:");
			puk2Label.setLabelFor(puk2Field);
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
		try {
			if (puk1Field.getPassword().length != PUK_SIZE
					|| puk2Field.getPassword().length != PUK_SIZE) {
				throw new RuntimeException("PUK size incorrect");
			}
			System.arraycopy(puk1Field.getPassword(), 0, puk1, 0, PUK_SIZE);
			System.arraycopy(puk2Field.getPassword(), 0, puk2, 0, PUK_SIZE);
		} finally {
			Arrays.fill(puk1Field.getPassword(), (char) 0);
			Arrays.fill(puk2Field.getPassword(), (char) 0);
		}
	}

	public static final class Pins {
		private final char[] oldPin;
		private final char[] newPin;

		public Pins(char[] oldPin, char[] newPin) {
			this.oldPin = new char[oldPin.length];
			this.newPin = new char[newPin.length];
			System.arraycopy(oldPin, 0, this.oldPin, 0, oldPin.length);
			System.arraycopy(newPin, 0, this.newPin, 0, newPin.length);
		}

		public char[] getOldPin() {
			return this.oldPin;
		}

		public char[] getNewPin() {
			return this.newPin;
		}
	}

	public Pins getPins(int retriesLeft) {
		Box mainPanel = Box.createVerticalBox();

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

		JPasswordField oldPinField = new JPasswordField(MAX_PIN_SIZE);
		{
			Box oldPinPanel = Box.createHorizontalBox();
			JLabel oldPinLabel = new JLabel(this.messages
					.getMessage(MESSAGE_ID.CURRENT_PIN)
					+ ":");
			oldPinLabel.setLabelFor(oldPinField);
			oldPinPanel.add(oldPinLabel);
			oldPinPanel.add(Box.createHorizontalStrut(5));
			oldPinPanel.add(oldPinField);
			mainPanel.add(oldPinPanel);
		}

		mainPanel.add(Box.createVerticalStrut(5));

		JPasswordField newPinField = new JPasswordField(MAX_PIN_SIZE);
		{
			Box newPinPanel = Box.createHorizontalBox();
			JLabel newPinLabel = new JLabel(this.messages
					.getMessage(MESSAGE_ID.NEW_PIN)
					+ ":");
			newPinLabel.setLabelFor(newPinField);
			newPinPanel.add(newPinLabel);
			newPinPanel.add(Box.createHorizontalStrut(5));
			newPinPanel.add(newPinField);
			mainPanel.add(newPinPanel);
		}

		mainPanel.add(Box.createVerticalStrut(5));

		JPasswordField new2PinField = new JPasswordField(MAX_PIN_SIZE);
		{
			Box new2PinPanel = Box.createHorizontalBox();
			JLabel new2PinLabel = new JLabel(this.messages
					.getMessage(MESSAGE_ID.NEW_PIN)
					+ ":");
			new2PinLabel.setLabelFor(new2PinField);
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
		Pins pins = new Pins(oldPinField.getPassword(), newPinField
				.getPassword());
		Arrays.fill(oldPinField.getPassword(), (char) 0);
		Arrays.fill(newPinField.getPassword(), (char) 0);
		return pins;
	}

	public char[] getPin() {
		return getPin(-1);
	}

	private JFrame pinPadFrame;

	public void showPINPadFrame(int retriesLeft) {
		showPINPadFrame(retriesLeft, "PIN", this.messages
				.getMessage(MESSAGE_ID.PIN_PAD));
	}

	private void showPINPadFrame(int retriesLeft, String title, String message) {
		if (null != this.pinPadFrame) {
			disposePINPadFrame();
		}
		this.pinPadFrame = new JFrame(title);
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
		panel.add(new JLabel(message));
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
		final JPasswordField passwordField = new JPasswordField(MAX_PIN_SIZE);
		promptLabel.setLabelFor(passwordField);
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
		final JButton okButton = new JButton(this.messages
				.getMessage(MESSAGE_ID.OK));
		okButton.setEnabled(false);
		buttonPanel.add(okButton);
		JButton cancelButton = new JButton(this.messages
				.getMessage(MESSAGE_ID.CANCEL));
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
				int pinSize = passwordField.getPassword().length;
				if (MIN_PIN_SIZE <= pinSize && pinSize <= MAX_PIN_SIZE) {
					dialogResult.result = DialogResult.Result.OK;
					dialog.dispose();
				}
			}
		});
		passwordField.addKeyListener(new KeyListener() {

			public void keyPressed(KeyEvent e) {
			}

			public void keyReleased(KeyEvent e) {
				int pinSize = passwordField.getPassword().length;
				if (MIN_PIN_SIZE <= pinSize && pinSize <= MAX_PIN_SIZE) {
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

	public void showPUKPadFrame(int retriesLeft) {
		showPINPadFrame(retriesLeft, "eID PIN unblock", this.messages
				.getMessage(MESSAGE_ID.PUK_PAD));
	}

	public void showPINChangePadFrame(int retriesLeft) {
		showPINPadFrame(retriesLeft, "eID PIN change", this.messages
				.getMessage(MESSAGE_ID.PIN_PAD_CHANGE));
	}

	public void showPINModifyOldPINFrame(int retriesLeft) {
		showPINPadFrame(retriesLeft, "eID PIN change", this.messages
				.getMessage(MESSAGE_ID.PIN_PAD_MODIFY_OLD));
	}

	public void showPINModifyNewPINFrame(int retriesLeft) {
		showPINPadFrame(retriesLeft, "eID PIN change", this.messages
				.getMessage(MESSAGE_ID.PIN_PAD_MODIFY_NEW));
	}

	public void showPINModifyNewPINAgainFrame(int retriesLeft) {
		showPINPadFrame(retriesLeft, "eID PIN change", this.messages
				.getMessage(MESSAGE_ID.PIN_PAD_MODIFY_NEW_AGAIN));
	}
}
