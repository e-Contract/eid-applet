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

    /**
     * Set if applet must send citizen's photo
     *
     * @todo setHeader instead of addHeader
     */
    public function setIncludePhoto($bool = FALSE) {
        $this->addHeader(BEIDMessageHeader::INCLUDE_PHOTO, $bool);
    }
    /**
     * Set if applet must send citizen's address info
     *
     * @param boole $bool
     */
    public function setIncludeAddress($bool = FALSE) {
        $this->addHeader(BEIDMessageHeader::INCLUDE_ADDRESS, $bool);
    }

    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct();
        $this->setProtocolType(BEIDMessageType::ID_REQUEST);
        $this->createResponse();
    }
}
?>
