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

    /**
     * Get challenge (20 random bytes)
     *
     * @return string
     */
    public function getChallenge() {
        return $this->challenge;
    }

    /**
     * Constructor
     *
     * @todo use openssl_pseudo_bytes in PHP 5.3
     */
    public function __construct() {
        parent::__construct();

        /* create a challenge (20 random bytes) */
        $tmp = '';
        for ($i = 0; $i < 20; $i++) {
            $tmp .= chr(mt_rand(1,255));
        }
        $this->challenge = $tmp;

        $this->setProtocolType(BEIDMessageType::AUTH_REQUEST);
        $this->createResponse();
        $this->setBody($this->challenge);
    }
}
?>
