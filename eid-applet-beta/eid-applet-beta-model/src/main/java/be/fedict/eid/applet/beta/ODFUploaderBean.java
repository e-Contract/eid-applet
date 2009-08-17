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

package be.fedict.eid.applet.beta;

import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;

@Stateful
@Name("odfUploader")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/ODFUploaderBean")
public class ODFUploaderBean implements ODFUploader {

	@Logger
	private Log log;

	private String fileName;

	private byte[] uploadedFile;

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}

	public String getFileName() {
		return this.fileName;
	}

	public byte[] getUploadedFile() {
		return this.uploadedFile;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public void setUploadedFile(byte[] uploadedFile) {
		this.uploadedFile = uploadedFile;
	}

	public String upload() {
		this.log.debug("upload: " + this.fileName);
		this.log.debug("file size: " + this.uploadedFile.length);
		return "success";
	}
}
