README for FedICT eID Applet Project
====================================

=== 1. Introduction

This project contains the source core tree of the FedICT eID Applet.


=== 2. Requirements

The following is required for compiling the eID Applet software:
* Sun Java 1.6.0_11
* Apache Maven 2.0.9
* eToken with code signing certificate


=== 3. Build

The project can be build via:
	mvn clean install

This will also build a test web application EAR artifact named:
	eid-applet-test-deploy

Deploy the test web application to a local running JBoss AS 5.0.x via:
	cd eid-applet-test/eid-applet-test-deploy
	mvn jboss:undeploy jboss:deploy

We provide a JBoss AS 5.0.x package artifact named:
	eid-applet-jboss-as

Missing dependencies can be added to your local Maven repository via:
        mvn install:install-file -Dfile=Download/jboss-5.0.0.GA-jdk6.zip \
	-DgroupId=org.jboss -DartifactId=jboss-as-distribution \
	-Dversion=5.0.0.GA -Dpackaging=zip -DgeneratePom=true -Dclassifier=jdk6

During the build process an eToken is required to sign the applet JAR.
The eToken configuration is located in pom.xml under the eid-applet-package 
artifact.

You can speed up the development build cycle by skipping the unit tests via:
	mvn -Dmaven.test.skip=true clean install


=== 4. SDK Release

An SDK build can be performed via:
	mvn -Dhttp.proxyHost=proxy.yourict.net -Dhttp.proxyPort=8080 -Denv=sdk
clean install

The final artifact is located under:
	eid-applet-sdk/target/

An SDK release build should use the production eToken containing the official
FedICT code signing certificate.


=== 5. Eclipse IDE

The Eclipse project files can be created via:
	mvn -Denv=sdk eclipse:eclipse

Afterwards simply import the projects in Eclipse via:
	File -> Import... -> General:Existing Projects into Workspace

First time you use an Eclipse workspace you might need to add the maven 
repository location. Do this via:
    mvn eclipse:add-maven-repo -Declipse.workspace=<location of your workspace>


=== 6. License

The license conditions can be found in the file: LICENSE.txt


=== 7. Contact

The author can be contacted via: frank.cornelis@fedict.be
