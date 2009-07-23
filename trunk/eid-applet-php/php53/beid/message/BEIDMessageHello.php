<?php
/**
 * Hello message
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageHello extends BEIDMessage {
    /**
     * Create and immediately send an Hello message
     */
    public static function createAndSend() {
        $msg = new BEIDMessageHello();
        $msg->createResponse();
        $msg->send();
    }

    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct();
        $this->setProtocolType(BEIDMessageType::HELLO);
    }
}
?>
