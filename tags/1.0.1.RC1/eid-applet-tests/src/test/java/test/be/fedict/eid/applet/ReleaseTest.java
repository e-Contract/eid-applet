/*
 * eID Applet Project.
 * Copyright (C) 2009 FedICT.
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.sun.org.apache.xpath.internal.XPathAPI;

/**
 * We do our own release process since we're not really happy with the
 * maven-release-plugin.
 * 
 * @author Frank Cornelis
 * 
 */
public class ReleaseTest {

	private static final Log LOG = LogFactory.getLog(ReleaseTest.class);

	// 1.0.0-SNAPSHOT
	private static final String CURRENT_VERSION = "1.0.1-SNAPSHOT";

	// 1.0.0-rc-3
	private static final String NEW_VERSION = "1.0.1.RC1";

	@Test
	public void testVersioning() throws Exception {
		Thread thread = Thread.currentThread();
		ClassLoader classLoader = thread.getContextClassLoader();
		String classResourceName = ReleaseTest.class.getName().replaceAll(
				"\\.", "\\/")
				+ ".class";
		URL classUrl = classLoader.getResource(classResourceName);
		LOG.debug("class URL: " + classUrl);
		URL baseUrl = new URL(
				classUrl
						.toString()
						.substring(
								0,
								classUrl
										.toString()
										.indexOf(
												"eid-applet-tests/target/test-classes/test/be/fedict/eid/applet/ReleaseTest.class")));
		LOG.debug("base URL: " + baseUrl);
		File baseDir = new File(baseUrl.toURI());
		List<File> pomFiles = new LinkedList<File>();
		getPomFiles(baseDir, pomFiles);
		LOG.debug("# pom.xml files: " + pomFiles.size());
		for (File pomFile : pomFiles) {
			LOG.debug("pom.xml: " + pomFile.getAbsolutePath());
			Document pomDocument = loadDocument(pomFile);
			NodeList dependencyVersionTextNodeList = XPathAPI
					.selectNodeList(
							pomDocument.getDocumentElement(),
							"//:dependency[:groupId/text()='be.fedict.eid-applet']/:version/text()",
							pomDocument.getDocumentElement());
			LOG.debug("# dependency nodes: "
					+ dependencyVersionTextNodeList.getLength());
			for (int idx = 0; idx < dependencyVersionTextNodeList.getLength(); idx++) {
				Node dependencyVersionTextNode = dependencyVersionTextNodeList
						.item(idx);
				assertEquals(CURRENT_VERSION, dependencyVersionTextNode
						.getNodeValue());
				dependencyVersionTextNode.setNodeValue(NEW_VERSION);
			}

			Node projectVersionTextNode = XPathAPI
					.selectSingleNode(
							pomDocument.getDocumentElement(),
							"/:project[:groupId[contains(text(), 'be.fedict')]]/:version/text()",
							pomDocument.getDocumentElement());
			if (null != projectVersionTextNode) {
				assertEquals(CURRENT_VERSION, projectVersionTextNode
						.getNodeValue());
				projectVersionTextNode.setNodeValue(NEW_VERSION);
			}

			Node parentVersionTextNode = XPathAPI
					.selectSingleNode(
							pomDocument.getDocumentElement(),
							"/:project/:parent[:groupId[contains(text(), 'be.fedict')]]/:version/text()",
							pomDocument.getDocumentElement());
			if (null != parentVersionTextNode) {
				assertEquals(CURRENT_VERSION, parentVersionTextNode
						.getNodeValue());
				parentVersionTextNode.setNodeValue(NEW_VERSION);
			}

			NodeList pluginVersionTextNodeList = XPathAPI
					.selectNodeList(
							pomDocument.getDocumentElement(),
							"//:plugins//:plugin[:groupId/text()='be.fedict.eid-applet']/:version/text()",
							pomDocument.getDocumentElement());
			LOG.debug("# plugin nodes: "
					+ pluginVersionTextNodeList.getLength());
			for (int idx = 0; idx < pluginVersionTextNodeList.getLength(); idx++) {
				Node pluginVersionTextNode = pluginVersionTextNodeList
						.item(idx);
				assertEquals(CURRENT_VERSION, pluginVersionTextNode
						.getNodeValue());
				pluginVersionTextNode.setNodeValue(NEW_VERSION);
			}

			storeDocument(pomDocument, pomFile);
		}
	}

	private void getPomFiles(File dir, List<File> pomFiles) {
		File[] files = dir.listFiles();
		for (File file : files) {
			if ("pom.xml".equals(file.getName())) {
				pomFiles.add(file);
			}
			if (file.isDirectory()) {
				getPomFiles(file, pomFiles);
			}
		}
	}

	private Document loadDocument(File file)
			throws ParserConfigurationException, SAXException, IOException {
		FileInputStream documentInputStream = new FileInputStream(file);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(documentInputStream);
		return document;
	}

	private void storeDocument(Document document, File file)
			throws FileNotFoundException, TransformerException {
		OutputStream outputStream = new FileOutputStream(file);
		Source source = new DOMSource(document);
		Result result = new StreamResult(outputStream);
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.transform(source, result);
	}
}
