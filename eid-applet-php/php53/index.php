<!--
/**
 * Index page
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */
-->
<html>
    <head>
		<title>BEID PHP test page</title>
	</head>
    <body>
        <h1>BEID PHP test page</h1>
		<p><strong>Warning: alpha quality, do not use this in a production environment</strong></p>
        <ul>
            <li><a href="demoAuthentication.php">Authentication demo</a></li>
            <li><a href="demoCheckClient.php">Check client environment demo</a></li>
            <li><a href="demoIdentity.php">Identity demo</a></li>
        </ul>
                <hr/>
                <p>TODO list:</p>
                <ul>
                    <li>use memcached for sessions</li>
                    <li>check where $_SESSION is used</li>
                    <li>use PHP 5.3 (DateTime serialization, openssl_pseudo_bytes)</li>
                    <li>more exception handling</li>
                    <li>implement finite state machine for protocol checks</li>
                    <li>unit tests</li>
                    <li>...</li>
                </ul>
    </body>
</html>