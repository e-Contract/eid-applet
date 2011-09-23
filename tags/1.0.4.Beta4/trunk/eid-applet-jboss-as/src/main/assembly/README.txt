FedICT eID Applet JBoss Application Server Distribution
=======================================================

=== 1. Introduction

This package contains a JBoss Application Server configured to ease the
development of the FedICT eID Applet. It is based on JBoss AS 6.0.0.Final.

We provide two server configurations. The "default" and the "all".


=== 2. Starting the server using the "default" configuration

Under Linux execute the following:
	cd bin
	./run.sh &

To bind JBoss AS on all network interfaces, start the server as follows:
	cd bin
	./run.sh -b 0.0.0.0 &


=== 3. Starting the server using the "all" cluster configuration

Under Linux execute the following:
	cd bin
	./run.sh -c all &

To bind JBoss AS on all network interfaces, start the server as follows:
	cd bin
	./run.sh -c all -b 0.0.0.0 &


=== 4. Stopping the server

Ctrl-C if the JBoss AS runs in the foreground.
If JBoss AS runs in the background then execute the following:
	cd bin
	./shutdown.sh -S
