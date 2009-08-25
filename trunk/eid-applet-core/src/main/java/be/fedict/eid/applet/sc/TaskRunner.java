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

package be.fedict.eid.applet.sc;

import be.fedict.eid.applet.View;

/**
 * Task runner for smart card specific operations. Will run a given task using
 * some back-off strategy in case of failure.
 * 
 * @author Frank Cornelis
 * 
 */
public class TaskRunner {

	private static final int TRIES = 3;

	private static final int BACKOFF_SLEEP = 1000 * 2;

	private final PcscEidSpi pcscEidSpi;

	private final View view;

	/**
	 * Main constructor.
	 * 
	 * @param pcscEidSpi
	 * @param view
	 */
	public TaskRunner(PcscEidSpi pcscEidSpi, View view) {
		this.pcscEidSpi = pcscEidSpi;
		this.view = view;
	}

	public <T> T run(Task<T> task) {
		int tries = TRIES;
		while (tries != 0) {
			try {
				T result = task.run();
				return result;
			} catch (Exception e) {
				addDetailMessage("task exception detected: " + e.getMessage());
				addDetailMessage("exception type: " + e.getClass().getName());
				Throwable cause = e.getCause();
				if (null != cause) {
					addDetailMessage("exception cause: " + cause.getMessage());
					addDetailMessage("exception cause type: "
							+ cause.getClass().getName());
				}
				addDetailMessage("will sleep and retry...");
			}
			try {
				Thread.sleep(BACKOFF_SLEEP);
			} catch (InterruptedException e) {
				throw new RuntimeException("error sleeping");
			}
			tries--;
			/*
			 * Because software like ActivClient select the JavaCard card
			 * manager to browse the available JavaCard applets on inserted
			 * smart cards, we risk of not having the Belpic JavaCard applet
			 * selected per default. To circumvent this situation we explicitly
			 * select the Belpic JavaCard applet after a failed eID APDU
			 * sequence.
			 */
			this.pcscEidSpi.selectBelpicJavaCardApplet();
		}
		throw new RuntimeException("maximum tries exceeded. I give up.");
	}

	private void addDetailMessage(String detailMessage) {
		this.view.addDetailMessage(detailMessage);
	}
}
