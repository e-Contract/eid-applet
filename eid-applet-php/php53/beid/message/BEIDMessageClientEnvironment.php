<?php
/**
 * Client environment message
 *
 * @package BEIDApplet
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageClientEnvironment extends BEIDMessage {
    
    /**
     * Get client environment of the applet, like the browser and java version
     *
     * @param HttpMessage $request
     * @todo add more exception handling code
     */
    public function getClientEnvironment(HttpMessage $request) {
        $stream = HttpResponse::getRequestBodyStream();

        $client = new BEIDClientEnvironment();

        /* JVM the applet is running in */
        $javaVendor = $request->getHeader(BEIDMessageHeader::JAVA_VENDOR);
        $javaVersion = $request->getHeader(BEIDMessageHeader::JAVA_VERSION);

        $client->setJavaVendor($javaVendor);
        $client->setJavaVersion($javaVersion);

        /* browser */
        $navigatorUA = $request->getHeader(BEIDMessageHeader::NAVIGATOR_UA);
        $navigatorName = $request->getHeader(BEIDMessageHeader::NAVIGATOR_NAME);
        $navigatorVersion = $request->getHeader(BEIDMessageHeader::NAVIGATOR_VERSION);

        $client->setNavigatorUA($navigatorUA);
        $client->setNavigatorName($navigatorName);
        $client->setNavigatorVersion($navigatorVersion);

        /* readers */
        $eidReaders = stream_get_contents($stream);
        $client->setReaders($eidReaders);

        $_SESSION['Configuration'] = $client;
        return $client;
    }

    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct();
        $this->setProtocolType(BEIDMessageType::CLIENT_DATA);
    }
}
?>
