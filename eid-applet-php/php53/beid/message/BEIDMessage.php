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

    /**
     * Get protocol type (message type)
     * @see BEIDMessageType
     *
     * @return string
     */
    public function getProtocolType() {
        return $this->protocolType;
    }
    /**
     * Set protocol type
     *
     * @param string $protocolType
     */
    public function setProtocolType($protocolType) {
        $this->protocolType = $protocolType;
    }

    /**
     * Get protocol version, currently this is always '1'
     *
     * @return string
     */
    public function getProtocolVersion() {
        return $this->protocolVersion;
    }
    /**
     * Set protocol version as a string of number(s)
     *
     * @param string $protocolVersion
     */
    public function setProtocolVersion($protocolVersion) {
        $this->protocolVersion = $protocolVersion;
    }

    /**
     * Get the HTTP response
     *
     * @return HttpMessage
     */
    public function getResponse() {
        return $this->response;
    }
    /**
     * Set the HTTP response
     *
     * @param HttpMessage $response
     */
    public function setResponse(HttpMessage $response) {
        $this->response = $response;
    }

    /**
     * Create HTTP response
     *
     * @return HttpMessage
     */
    public function createResponse() {
        $this->response = HttpMessage::fromEnv(HttpMessage::TYPE_RESPONSE);
        $this->response->addHeaders(array(
                BEIDMessageHeader::VERSION => '1',
                BEIDMessageHeader::TYPE => $this->getProtocolType()
            ));
        return $this->response;
    }

    /**
     * Add an HTTP header
     * @see BEIDMessageHeader
     *
     * @param string $header
     * @param string $value
     */
    public function addHeader($header, $value) {
        $this->response->addHeaders(array($header => $value));
    }

    /**
     * Set the HTTP response code
     *
     * @param int $code
     */
    public function setResponseCode($code) {
        if (! is_integer($code)) {
            throw new BEIDMessageException('Message reponse code must be integer');
        }
        $this->response->setResponseCode($code);
    }

    /**
     * Set the HTTP response body
     * @param string $body
     */
    public function setBody($body) {
        $this->response->setBody($body);
    }
    
    /**
     * Send the HTTP message
     */
    public function send() {
        $this->response->send();
    }

    /**
     * Empty constructor
     */
    public function __construct() {
    }

    /**
     * "Magic" PHP method
     * @return string
     */
    public function __toString() {
        return $this->getProtocolType();
    }
}
?>
