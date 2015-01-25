/*
 * eID Applet Project.
 * Copyright (C) 2011-2014 e-Contract.be BVBA.
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

import java.util.LinkedList;
import java.util.List;

public class Program {

	private final List<Instruction> instructions;

	public Program() {
		this.instructions = new LinkedList<Instruction>();
	}

	public List<Instruction> getInstructions() {
		return this.instructions;
	}

	public void addInstruction(Instruction instruction) {
		this.instructions.add(instruction);
	}

	@Override
	public String toString() {
		StringBuilder stringBuilder = new StringBuilder();
		for (Instruction instruction : this.instructions) {
			stringBuilder.append(instruction.toString() + "\n");
		}
		return stringBuilder.toString();
	}
}
