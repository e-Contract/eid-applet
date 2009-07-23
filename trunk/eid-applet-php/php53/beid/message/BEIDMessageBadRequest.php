<?php
/**
 * Bad request message
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageBadRequest extends BEIDMessage {
    /**
     * Create and immediately send a bad request message
     *
     * @param string $message
     */
    public static function createAndSend($message) {
        $msg = new BEIDMessageBadRequest();
        $msg->setBody('<html><body>'.$message.'</body></html>');
        $msg->send();
    }

    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct();
        $this->createResponse();
        $this->setResponseCode(400);
    }
}
?>
