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

public class Interpreter {

	private final Program program;

	private final Runtime runtime;

	private State state;

	public Interpreter(Program program, Runtime runtime) {
		this.program = program;
		this.runtime = runtime;
	}

	public void run() {
		this.state = new State();
		while (this.state.isRunning()) {
			int instructionPointer = this.state.getInstructionPointer();
			Instruction instruction = this.program.getInstructions().get(
					instructionPointer);
			instruction.execute(this.state, this.runtime);
		}
	}

	public int getVariable(String variableName) {
		return this.state.getVariable(variableName);
	}
}
