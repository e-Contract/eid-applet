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

package be.fedict.eid.applet.maven.sql.ddl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.persistence.Entity;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.factory.ArtifactFactory;
import org.apache.maven.artifact.resolver.ArtifactNotFoundException;
import org.apache.maven.artifact.resolver.ArtifactResolutionException;
import org.apache.maven.artifact.resolver.ArtifactResolver;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.IOUtil;
import org.codehaus.plexus.util.StringUtils;
import org.hibernate.cfg.AnnotationConfiguration;
import org.hibernate.dialect.Dialect;
import org.hibernate.tool.hbm2ddl.SchemaExport;
import org.scannotation.AnnotationDB;

/**
 * Maven2 plugin to generate SQL DDL scripts out of JPA entities.
 * 
 * <p>
 * Test via:
 * <code>mvn be.fedict.eid-applet:eid-applet-sql-ddl-plugin:1.0.2-SNAPSHOT:generate-sql-ddl</code>
 * </p>
 * 
 * @author Frank Cornelis
 * @goal generate-sql-ddl
 */
public class SQLDDLMojo extends AbstractMojo {

	/**
	 * Directory containing the generated docbook XML.
	 * 
	 * @parameter expression="${project.build.directory}"
	 * @required
	 */
	private File outputDirectory;

	/**
	 * Name of the generated SQL DDL script.
	 * 
	 * @parameter
	 * @required
	 */
	private String outputName;

	/**
	 * Name of the Hibernate dialect to be used for SQL DDL script generation.
	 * 
	 * @parameter
	 * @required
	 */
	private String hibernateDialect;

	/**
	 * POM
	 * 
	 * @parameter expression="${project}"
	 * @readonly
	 * @required
	 */
	protected MavenProject project;

	/**
	 * @parameter
	 * @required
	 */
	private ArrayList<ArtifactItem> artifactItems;

	/**
	 * Used to look up Artifacts in the remote repository.
	 * 
	 * @component
	 */
	protected ArtifactFactory artifactFactory;

	/**
	 * Used to look up Artifacts in the remote repository.
	 * 
	 * @component
	 */
	protected ArtifactResolver resolver;

	/**
	 * List of Remote Repositories used by the resolver
	 * 
	 * @parameter expression="${project.remoteArtifactRepositories}"
	 * @readonly
	 * @required
	 */
	protected java.util.List remoteRepos;

	/**
	 * Location of the local repository.
	 * 
	 * @parameter expression="${localRepository}"
	 * @readonly
	 * @required
	 */
	private org.apache.maven.artifact.repository.ArtifactRepository local;

	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		getLog().info("SQL DDL script generator");

		File outputFile = new File(this.outputDirectory, this.outputName);
		getLog().info(
				"Output SQL DDL script file: " + outputFile.getAbsolutePath());

		this.outputDirectory.mkdirs();
		try {
			outputFile.createNewFile();
		} catch (IOException e) {
			throw new MojoExecutionException("I/O error.", e);
		}

		for (ArtifactItem artifactItem : this.artifactItems) {
			getLog().info(
					"artifact: " + artifactItem.getGroupId() + ":"
							+ artifactItem.getArtifactId());
			List<Dependency> dependencies = this.project.getDependencies();
			String version = null;
			for (Dependency dependency : dependencies) {
				if (StringUtils.equals(dependency.getArtifactId(),
						artifactItem.getArtifactId())
						&& StringUtils.equals(dependency.getGroupId(),
								artifactItem.getGroupId())) {
					version = dependency.getVersion();
					break;
				}
			}
			getLog().info("artifact version: " + version);
			VersionRange versionRange = VersionRange.createFromVersion(version);
			Artifact artifact = this.artifactFactory.createDependencyArtifact(
					artifactItem.getGroupId(), artifactItem.getArtifactId(),
					versionRange, "jar", null, Artifact.SCOPE_COMPILE);
			try {
				this.resolver.resolve(artifact, this.remoteRepos, this.local);
			} catch (ArtifactResolutionException e) {
				throw new MojoExecutionException("Unable to resolve artifact.",
						e);
			} catch (ArtifactNotFoundException e) {
				throw new MojoExecutionException("Unable to find artifact.", e);
			}
			getLog().info(
					"artifact file: " + artifact.getFile().getAbsolutePath());
			getLog().info("hibernate dialect: " + this.hibernateDialect);

			URL artifactUrl;
			try {
				artifactUrl = artifact.getFile().toURI().toURL();
			} catch (MalformedURLException e) {
				throw new MojoExecutionException("URL error.", e);
			}

			URLClassLoader classLoader = new URLClassLoader(
					new URL[] { artifactUrl }, this.getClass().getClassLoader());
			Thread.currentThread().setContextClassLoader(classLoader);

			AnnotationDB annotationDb = new AnnotationDB();
			try {
				annotationDb.scanArchives(artifactUrl);
			} catch (IOException e) {
				throw new MojoExecutionException("I/O error.", e);
			}
			Set<String> classNames = annotationDb.getAnnotationIndex().get(
					Entity.class.getName());
			getLog().info("# JPA entity classes: " + classNames.size());

			AnnotationConfiguration configuration = new AnnotationConfiguration();

			configuration.setProperty("hibernate.dialect",
					this.hibernateDialect);
			Dialect dialect = Dialect.getDialect(configuration.getProperties());
			getLog().info("dialect: " + dialect.toString());

			for (String className : classNames) {
				getLog().info("JPA entity: " + className);
				Class<?> entityClass;
				try {
					entityClass = classLoader.loadClass(className);
					getLog().info(
							"entity class loader: "
									+ entityClass.getClassLoader());
				} catch (ClassNotFoundException e) {
					throw new MojoExecutionException("class not found.", e);
				}
				configuration.addAnnotatedClass(entityClass);
			}

			SchemaExport schemaExport = new SchemaExport(configuration);
			schemaExport.setOutputFile(outputFile.getAbsolutePath());
			schemaExport.setDelimiter(";");

			try {
				getLog().info(
						"SQL DDL script: "
								+ IOUtil.toString(new FileInputStream(
										outputFile)));
			} catch (FileNotFoundException e) {
				throw new MojoExecutionException("file not found.", e);
			} catch (IOException e) {
				throw new MojoExecutionException("I/O error.", e);
			}

			// operate
			schemaExport.execute(true, false, false, false);
			List<Exception> exceptions = schemaExport.getExceptions();
			for (Exception exception : exceptions) {
				getLog().error("exception: " + exception.getMessage());
			}
		}
	}
}
