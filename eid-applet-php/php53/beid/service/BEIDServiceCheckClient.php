<?php
/**
 * Check client environment service
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDServiceCheckClient {
    /**
     * Handles the conversation between the server and the EID applet.
     * This conversation is done using HTTP requests and responses
     */
    public function processRequest() {
        $msg = NULL;

        $request = HttpMessage::fromEnv(HttpMessage::TYPE_REQUEST);
        try {
            $msg = BEIDMessageFactory::createFromRequest($request);
        } catch (BEIDMessageException $mex) {
            BEIDMessageBadRequest::createAndSend($mex->getMessage());
            throw new BEIDMessageException('Bad request');
        }

        switch(true) {
            case $msg instanceof BEIDMessageHello :
                BEIDMessageCheckClient::createAndSend();
                break;

            case $msg instanceof BEIDMessageClientEnvironment :
                $configuration = $msg->getClientEnvironment($request);
                BEIDMessageFinished::createAndSend();
                break;

            default:
                BEIDMessageBadRequest::createAndSend('Bad request '.$messageType);
                throw new BEIDMessageException('Bad request'.$messageType);
                break;
        }
    }
}
?>
