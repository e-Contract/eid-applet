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

import java.io.File;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.log.Log;

@Stateful
@Name("odfUploader")
@LocalBinding(jndiBinding = "fedict/eid/applet/beta/ODFUploaderBean")
@Scope(ScopeType.SESSION)
public class ODFUploaderBean implements ODFUploader {

	@Logger
	private Log log;

	private List<File> files;

	public ODFUploaderBean() {
		this.files = new LinkedList<File>();
	}

	public List<File> getFiles() {
		this.log.debug("get files");
		return this.files;
	}

	public void setFiles(List<File> files) {
		this.log.debug("set files");
		this.files = files;
	}

	public int getSize() {
		int size = this.files.size();
		this.log.debug("get size: " + size);
		return size;
	}

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}
}
