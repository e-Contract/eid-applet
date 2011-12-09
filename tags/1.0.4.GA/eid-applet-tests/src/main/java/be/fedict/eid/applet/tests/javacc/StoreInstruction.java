/*
 * eID Applet Project.
 * Copyright (C) 2011 Frank Cornelis.
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

package be.fedict.eid.applet.tests.javacc;

public class StoreInstruction implements Instruction {

	private final String variableName;

	private final int value;

	public StoreInstruction(String variableName, int value) {
		this.variableName = variableName;
		this.value = value;
	}

	@Override
	public void execute(State state, Runtime runtime) {
		state.store(this.variableName, this.value);
		state.increaseInstructionPointer();
	}

	@Override
	public String toString() {
		return "STORE " + this.variableName + " = " + this.value;
	}
}
