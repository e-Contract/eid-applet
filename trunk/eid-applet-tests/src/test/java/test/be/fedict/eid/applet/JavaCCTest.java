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

package test.be.fedict.eid.applet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.easymock.EasyMock;
import org.junit.Test;

import be.fedict.eid.applet.tests.javacc.Instruction;
import be.fedict.eid.applet.tests.javacc.Interpreter;
import be.fedict.eid.applet.tests.javacc.OutputInstruction;
import be.fedict.eid.applet.tests.javacc.Program;
import be.fedict.eid.applet.tests.javacc.StopInstruction;
import be.fedict.eid.applet.tests.javacc.adder.Adder;
import be.fedict.eid.applet.tests.javacc.adder.ParseException;
import be.fedict.eid.applet.tests.javacc.adder2.Adder2;
import be.fedict.eid.applet.tests.javacc.adder3.Adder3;
import be.fedict.eid.applet.tests.javacc.calc.Calculator;
import be.fedict.eid.applet.tests.javacc.calc1.Calculator1;
import be.fedict.eid.applet.tests.javacc.calc2.Calculator2;
import be.fedict.eid.applet.tests.javacc.calc3.Calculator3;
import be.fedict.eid.applet.tests.javacc.lang.Language;

/**
 * JavaCC spike.
 * 
 * @author Frank Cornelis
 * 
 */
public class JavaCCTest {

	private static final Log LOG = LogFactory.getLog(JavaCCTest.class);

	@Test
	public void testAdder() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"1 + 2\n".getBytes());
		Adder adder = new Adder(inputStream);
		adder.Start();
	}

	@Test
	public void testAdderSyntaxError() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"1 + 2 +\n".getBytes());
		Adder adder = new Adder(inputStream);
		try {
			adder.Start();
			fail();
		} catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testAdder2() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"1 + 2\n".getBytes());
		Adder2 adder = new Adder2(inputStream);
		int result = adder.Start();
		LOG.debug("result: " + result);
		assertEquals(3, result);
	}

	@Test
	public void testAdder3() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"2 + 3\n".getBytes());
		Adder3 adder = new Adder3(inputStream);
		int result = adder.Start();
		LOG.debug("result: " + result);
		assertEquals(5, result);
	}

	@Test
	public void testCalculator() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"2 + 3.\n.1 + 1.5\n".getBytes());
		Calculator calculator = new Calculator(inputStream);
		calculator.Start(System.out);
	}

	@Test
	public void testCalculator1() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"2 + 3.\n.1 - 1.5\n".getBytes());
		Calculator1 calculator = new Calculator1(inputStream);
		calculator.Start(System.out);
	}

	@Test
	public void testCalculator2() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"2 + 3.\n.1 - 1.5\n2 * 3\n1 + 2 * 3\n".getBytes());
		Calculator2 calculator = new Calculator2(inputStream);
		calculator.Start(System.out);
	}

	@Test
	public void testCalculator3() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"2 + 3.\n.1 - 1.5\n2 * 3\n- (1 + 2) * 3\n".getBytes());
		Calculator3 calculator = new Calculator3(inputStream);
		calculator.Start(System.out);
	}

	@Test
	public void testLanguage() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"BEGIN END".getBytes());
		Language language = new Language(inputStream);
		language.Start();
	}

	@Test
	public void testLanguageNewLines() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"\rBEGIN\nEND\n \n".getBytes());
		Language language = new Language(inputStream);
		language.Start();
	}

	@Test
	public void testLanguageExit() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"BEGIN\nEXIT\nEND".getBytes());
		Language language = new Language(inputStream);
		language.Start();
	}

	@Test
	public void testLanguageOutput() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"BEGIN\nOUT 1234\nEND".getBytes());
		Language language = new Language(inputStream);
		Program program = language.Start();
		assertNotNull(program);
		List<Instruction> programInstructions = program.getInstructions();
		assertNotNull(programInstructions);
		assertEquals(2, programInstructions.size());

		Instruction instruction = programInstructions.get(0);
		assertTrue(instruction instanceof OutputInstruction);
		OutputInstruction outputInstruction = (OutputInstruction) instruction;
		assertEquals(1234, outputInstruction.getValue());

		Instruction instruction2 = programInstructions.get(1);
		assertTrue(instruction2 instanceof StopInstruction);
	}

	@Test
	public void testLanguageOutput2() throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				"BEGIN\nOUT 1234\nOUT 5678\nEND".getBytes());
		Language language = new Language(inputStream);
		Program program = language.Start();
		assertNotNull(program);
		List<Instruction> programInstructions = program.getInstructions();
		assertNotNull(programInstructions);
		assertEquals(3, programInstructions.size());

		Instruction instruction = programInstructions.get(0);
		assertTrue(instruction instanceof OutputInstruction);
		OutputInstruction outputInstruction = (OutputInstruction) instruction;
		assertEquals(1234, outputInstruction.getValue());

		Instruction instruction2 = programInstructions.get(1);
		assertTrue(instruction2 instanceof OutputInstruction);
		OutputInstruction outputInstruction2 = (OutputInstruction) instruction2;
		assertEquals(5678, outputInstruction2.getValue());

		be.fedict.eid.applet.tests.javacc.Runtime mockRuntime = EasyMock
				.createMock(be.fedict.eid.applet.tests.javacc.Runtime.class);
		Interpreter interpreter = new Interpreter(program, mockRuntime);

		mockRuntime.output(1234);
		mockRuntime.output(5678);

		EasyMock.replay(mockRuntime);
		interpreter.run();
		EasyMock.verify(mockRuntime);
	}
}
