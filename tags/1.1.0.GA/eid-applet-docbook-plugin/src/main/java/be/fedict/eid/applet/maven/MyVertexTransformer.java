/*
 * eID Applet Project.
 * Copyright (C) 2008-2010 FedICT.
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

package be.fedict.eid.applet.maven;

import java.awt.Color;
import java.awt.Paint;
import java.util.List;

import org.apache.commons.collections15.Transformer;

public class MyVertexTransformer implements Transformer<String, Paint> {

	private final String startMessage;

	private final List<String> stopMessages;

	public MyVertexTransformer(String startMessage, List<String> stopMessages) {
		this.startMessage = startMessage;
		this.stopMessages = stopMessages;
	}

	public Paint transform(String vertexName) {
		if (this.startMessage.equals(vertexName)) {
			return Color.GREEN;
		}
		if (this.stopMessages.contains(vertexName)) {
			return Color.RED;
		}
		return Color.WHITE;
	}
}