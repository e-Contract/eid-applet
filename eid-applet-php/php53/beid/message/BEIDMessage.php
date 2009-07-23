<?php
/**
 * Message super class, for messages being sent from and to the BEID applet
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessage {
    private $response;
    private $protocolType;
    private $protocolVersion;

    public function getProtocolType() {
        return $this->protocolType;
    }
    public function setProtocolType($protocolType) {
        $this->protocolType = $protocolType;
    }

    public function getProtocolVersion() {
        return $this->protocolVersion;
    }
    public function setProtocolVersion($protocolVersion) {
        $this->protocolVersion = $protocolVersion;
    }

    public function getResponse() {
        return $this->response;
    }
    public function setResponse($response) {
        $this->response = $response;
    }

    public function createResponse() {
        $this->response = HttpMessage::fromEnv(HttpMessage::TYPE_RESPONSE);
        $this->response->addHeaders(array(
                BEIDMessageHeader::VERSION => '1',
                BEIDMessageHeader::TYPE => $this->getProtocolType()
            ));
        return $this->response;
    }

    public function addHeader($header, $value) {
        $this->response->addHeaders(array($header => $value));
    }

    public function setResponseCode($code) {
        $this->response->setResponseCode($code);
    }
    public function setBody($body) {
        $this->response->setBody($body);
    }
    
    /**
     * Send the message
     */
    public function send() {
        $this->response->send();
    }

    public function __construct() {
    }

    public function __toString() {
        return $this->getProtocolType();
    }
}
?>
