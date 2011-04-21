/*
 * eID Applet Project.
 * Copyright (C) 2010 FedICT.
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

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.Paint;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;

import org.apache.commons.collections15.Transformer;
import org.apache.commons.collections15.map.HashedMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jgraph.JGraph;
import org.jgraph.graph.DefaultCellViewFactory;
import org.jgraph.graph.DefaultEdge;
import org.jgraph.graph.DefaultGraphCell;
import org.jgraph.graph.DefaultGraphModel;
import org.jgraph.graph.GraphConstants;
import org.jgraph.graph.GraphLayoutCache;
import org.jgraph.graph.GraphModel;
import org.junit.Test;

import be.fedict.eid.applet.shared.AppletProtocolMessageCatalog;
import be.fedict.eid.applet.shared.annotation.ProtocolStateAllowed;
import be.fedict.eid.applet.shared.annotation.ResponsesAllowed;
import be.fedict.eid.applet.shared.annotation.StartRequestMessage;
import be.fedict.eid.applet.shared.annotation.StateTransition;
import be.fedict.eid.applet.shared.annotation.StopResponseMessage;
import be.fedict.eid.applet.shared.protocol.ProtocolState;
import edu.uci.ics.jung.algorithms.layout.CircleLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.SparseMultigraph;
import edu.uci.ics.jung.graph.util.EdgeType;
import edu.uci.ics.jung.visualization.BasicVisualizationServer;
import edu.uci.ics.jung.visualization.decorators.ToStringLabeller;
import edu.uci.ics.jung.visualization.renderers.Renderer.VertexLabel.Position;

/**
 * Spike for JGraph usage.
 * 
 * @author Frank Cornelis
 * 
 */
public class JGraphTest {

	private static final Log LOG = LogFactory.getLog(JGraphTest.class);

	@Test
	public void testJGraph() throws Exception {
		GraphModel model = new DefaultGraphModel();
		GraphLayoutCache view = new GraphLayoutCache(model,
				new DefaultCellViewFactory());
		JGraph graph = new JGraph(model, view);

		DefaultGraphCell[] cells = new DefaultGraphCell[3];
		cells[0] = createCell("hello", true);
		cells[1] = createCell("world", false);
		DefaultEdge edge = new DefaultEdge();
		GraphConstants.setLineStyle(edge.getAttributes(),
				GraphConstants.ARROW_LINE);
		edge.setSource(cells[0].getChildAt(0));
		edge.setTarget(cells[1].getChildAt(0));
		cells[2] = edge;
		graph.getGraphLayoutCache().insert(cells);

		JOptionPane.showMessageDialog(null, new JScrollPane(graph));
	}

	private DefaultGraphCell createCell(String name, boolean raised) {
		DefaultGraphCell cell = new DefaultGraphCell(name);
		cell.addPort();
		GraphConstants.setBorder(cell.getAttributes(), BorderFactory
				.createRaisedBevelBorder());
		return cell;
	}

	@Test
	public void testJUNG2() throws Exception {
		Graph<String, String> graph = new SparseMultigraph<String, String>();
		graph.addVertex("state 1");
		graph.addVertex("state 2");
		graph.addVertex("state 3");
		graph.addVertex("state 4");
		graph.addVertex("state 5");
		graph.addVertex("state 6");
		graph.addEdge("edge 1", "state 1", "state 2", EdgeType.DIRECTED);
		graph.addEdge("edge 2", "state 1", "state 3", EdgeType.DIRECTED);
		graph.addEdge("edge 3", "state 1", "state 4", EdgeType.DIRECTED);
		graph.addEdge("edge 4", "state 3", "state 4", EdgeType.DIRECTED);

		CircleLayout<String, String> layout = new CircleLayout<String, String>(
				graph);
		layout.setSize(new Dimension(300, 300));

		BasicVisualizationServer<String, String> visualization = new BasicVisualizationServer<String, String>(
				layout);
		visualization.getRenderContext().setVertexLabelTransformer(
				new ToStringLabeller<String>());
		visualization.getRenderContext().setEdgeLabelTransformer(
				new ToStringLabeller<String>());
		visualization.setPreferredSize(new Dimension(350, 350));

		JOptionPane.showMessageDialog(null, visualization);
	}

	@Test
	public void testVisualizeProtocol() throws Exception {
		BasicVisualizationServer<String, String> visualization = createGraph();

		// JOptionPane.showMessageDialog(null, visualization);

		File tmpFile = File.createTempFile("graph-", ".png");
		graphToFile(visualization, tmpFile);
		LOG.debug("tmp file: " + tmpFile.getAbsolutePath());
	}

	private BasicVisualizationServer<String, String> createGraph() {
		AppletProtocolMessageCatalog catalog = new AppletProtocolMessageCatalog();
		List<Class<?>> catalogClasses = catalog.getCatalogClasses();

		Map<ProtocolState, List<String>> allowedProtocolStates = new HashedMap<ProtocolState, List<String>>();
		String startMessage = null;
		List<String> stopMessages = new LinkedList<String>();

		Graph<String, String> graph = new SparseMultigraph<String, String>();
		for (Class<?> messageClass : catalogClasses) {
			StartRequestMessage startRequestMessageAnnotation = messageClass
					.getAnnotation(StartRequestMessage.class);
			if (null != startRequestMessageAnnotation) {
				if (null != startMessage) {
					throw new RuntimeException(
							"only one single entry point possible");
				}
				startMessage = messageClass.getSimpleName();
			}
			StopResponseMessage stopResponseMessageAnnotation = messageClass
					.getAnnotation(StopResponseMessage.class);
			if (null != stopResponseMessageAnnotation) {
				stopMessages.add(messageClass.getSimpleName());
			}
			graph.addVertex(messageClass.getSimpleName());
			ProtocolStateAllowed protocolStateAllowedAnnotation = messageClass
					.getAnnotation(ProtocolStateAllowed.class);
			if (null != protocolStateAllowedAnnotation) {
				ProtocolState protocolState = protocolStateAllowedAnnotation
						.value();
				List<String> messages = allowedProtocolStates
						.get(protocolState);
				if (null == messages) {
					messages = new LinkedList<String>();
					allowedProtocolStates.put(protocolState, messages);
				}
				messages.add(messageClass.getSimpleName());
			}
		}

		LOG.debug("allowed protocol states: " + allowedProtocolStates);

		int edgeIdx = 0;
		for (Class<?> messageClass : catalogClasses) {
			ResponsesAllowed responsesAllowedAnnotation = messageClass
					.getAnnotation(ResponsesAllowed.class);
			if (null != responsesAllowedAnnotation) {
				Class<?>[] responseClasses = responsesAllowedAnnotation.value();
				for (Class<?> responseClass : responseClasses) {
					graph.addEdge("edge-" + edgeIdx, messageClass
							.getSimpleName(), responseClass.getSimpleName(),
							EdgeType.DIRECTED);
					edgeIdx++;
				}
			}
			StateTransition stateTransitionAnnotation = messageClass
					.getAnnotation(StateTransition.class);
			if (null != stateTransitionAnnotation) {
				ProtocolState protocolState = stateTransitionAnnotation.value();
				List<String> messages = allowedProtocolStates
						.get(protocolState);
				for (String message : messages) {
					graph.addEdge("edge-" + edgeIdx, messageClass
							.getSimpleName(), message, EdgeType.DIRECTED);
					edgeIdx++;
				}
			}
		}

		Layout<String, String> layout = new CircleLayout<String, String>(graph);
		layout.setSize(new Dimension(900, 650));

		BasicVisualizationServer<String, String> visualization = new BasicVisualizationServer<String, String>(
				layout);
		visualization.getRenderContext().setVertexLabelTransformer(
				new ToStringLabeller<String>());
		Transformer<String, Paint> myVertexTransformer = new MyVertexTransformer(
				startMessage, stopMessages);
		visualization.getRenderContext().setVertexFillPaintTransformer(
				myVertexTransformer);
		visualization.getRenderer().getVertexLabelRenderer().setPosition(
				Position.AUTO);
		visualization.setPreferredSize(new Dimension(900, 650));
		visualization.setBackground(Color.WHITE);
		return visualization;
	}

	private void graphToFile(
			BasicVisualizationServer<String, String> visualization, File file)
			throws IOException {
		Dimension size = visualization.getSize();
		int width = (int) (size.getWidth() + 1);
		int height = (int) (size.getHeight() + 1);
		LOG.debug("width: " + width);
		LOG.debug("height: " + height);
		BufferedImage bufferedImage = new BufferedImage(width, height,
				BufferedImage.TYPE_INT_ARGB);
		Graphics2D graphics = bufferedImage.createGraphics();
		graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
				RenderingHints.VALUE_ANTIALIAS_ON);
		graphics.setColor(Color.WHITE);
		graphics.fillRect(0, 0, 900, 650);
		visualization.setBounds(0, 0, 900, 650);
		visualization.paint(graphics);
		graphics.dispose();
		ImageIO.write(bufferedImage, "png", file);
	}

	public static class MyVertexTransformer implements
			Transformer<String, Paint> {

		private final String startMessage;

		private final List<String> stopMessages;

		public MyVertexTransformer(String startMessage,
				List<String> stopMessages) {
			this.startMessage = startMessage;
			this.stopMessages = stopMessages;
		}

		@Override
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
}
