<?php
/**
 * Identification request message
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageIdentificationRequest extends BEIDMessage {

    /** TODO create setHeader instead of addHeader **/
    public function setIncludePhoto($bool = FALSE) {
        $this->addHeader(BEIDMessageHeader::INCLUDE_PHOTO, $bool);
    }
    public function setIncludeAddress($bool = FALSE) {
        $this->addHeader(BEIDMessageHeader::INCLUDE_ADDRESS, $bool);
    }
    public function __construct() {
        parent::__construct();
        $this->setProtocolType(BEIDMessageType::ID_REQUEST);
        $this->createResponse();
    }
}
?>
