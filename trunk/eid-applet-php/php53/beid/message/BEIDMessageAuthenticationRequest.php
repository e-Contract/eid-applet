<?php
/**
 * Authentication request message
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageAuthenticationRequest extends BEIDMessage {
    private $challenge;


    public function getChallenge() {
        return $this->challenge;
    }

    public function __construct() {
        parent::__construct();

        /** TODO: openssl_pseudo_bytes in PHP 5.3 */
        $this->challenge = '1234567890abcdefghij';
        $this->setProtocolType(BEIDMessageType::AUTH_REQUEST);
        $this->createResponse();
        $this->setBody($this->challenge);
    }
}
?>
