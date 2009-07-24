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

package be.fedict.eid.applet.service;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.impl.handler.IdentityDataMessageHandler;

/**
 * Servlet to display the citizen's photo that is stored in the HTTP session
 * after a successful eID identification operation via the eID Applet.
 * 
 * @author fcorneli
 * 
 */
public class PhotoServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(PhotoServlet.class);

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		response.setContentType("image/jpg");
		response.setHeader("Cache-Control",
				"no-cache, no-store, must-revalidate, max-age=-1"); // http 1.1
		response.setHeader("Pragma", "no-cache, no-store"); // http 1.0
		response.setDateHeader("Expires", -1);
		ServletOutputStream out = response.getOutputStream();
		HttpSession session = request.getSession();
		byte[] photoData = (byte[]) session
				.getAttribute(IdentityDataMessageHandler.PHOTO_SESSION_ATTRIBUTE);
		if (null != photoData) {
			BufferedImage photo = ImageIO.read(new ByteArrayInputStream(
					photoData));
			if (null == photo) {
				/*
				 * In this case we render a photo containing some error message.
				 */
				photo = new BufferedImage(140, 200, BufferedImage.TYPE_INT_RGB);
				Graphics2D graphics = (Graphics2D) photo.getGraphics();
				RenderingHints renderingHints = new RenderingHints(
						RenderingHints.KEY_TEXT_ANTIALIASING,
						RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
				graphics.setRenderingHints(renderingHints);
				graphics.setColor(Color.WHITE);
				graphics.fillRect(1, 1, 140 - 1 - 1, 200 - 1 - 1);
				graphics.setColor(Color.RED);
				graphics.setFont(new Font("Dialog", Font.BOLD, 20));
				graphics.drawString("Photo Error", 0, 200 / 2);
				graphics.dispose();
				ImageIO.write(photo, "jpg", out);
			} else {
				out.write(photoData);
			}
		}
		out.close();
	}
}
