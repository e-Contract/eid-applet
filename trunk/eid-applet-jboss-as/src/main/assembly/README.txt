FedICT eID Applet JBoss Application Server Distribution
=======================================================

=== 1. Introduction

This package contains a JBoss Application Server configured to ease the
development of the FedICT eID Applet. It is based on JBoss AS 5.0.1.GA.


=== 2. Starting the server

Under Linux execute the following:
	cd bin
	./run.sh &


=== 3. Stopping the server

Ctrl-C if the JBoss AS runs in the foreground.
If JBoss AS runs in the background then execute the following:
	cd bin
	./shutdown.sh -S
