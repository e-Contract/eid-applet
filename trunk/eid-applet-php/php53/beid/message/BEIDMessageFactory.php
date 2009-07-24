<?php
/**
 * Message factory
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageFactory {
    /**
     * Create a BEID message from an HTTP request
     *
     * @param HTTPMessage $request
     * @return BEIDMessage or child class
     */
    public static function createFromRequest(HTTPMessage $request) {
        /* only accept POST requests */
        $method = $request->getRequestMethod();
        if ('GET' == $method) {
            throw new BEIDMessageException('The eID Applet Service should not be invoked directly.');
        }
        if ('POST' != $method) {
            throw new BEIDMessageException('Bad method '.$method);
        }

        /* verify protocol version */
        $version = $request->getHeader(BEIDMessageHeader::VERSION);
        if ('1' != $version) {
            throw new BEIDMessageException('Wrong protocol version '.$version);
        }
        $type = $request->getHeader(BEIDMessageHeader::TYPE);

        $msg = NULL;
        switch($type) {
            case BEIDMessageType::HELLO :
                $msg = new BEIDMessageHello();
                break;

            case BEIDMessageType::CLIENT_REQUEST :
                $msg = new BEIDMessageCheckClient();
                break;
            case BEIDMessageType::CLIENT_DATA :
                $msg = new BEIDMessageClientEnvironment();
                break;
            
            case BEIDMessageType::ID_DATA :
                $msg = new BEIDMessageIdentityData();
                break;
            case BEIDMessageType::ID_REQUEST :
                $msg = new BEIDMessageIdentificationRequest();
                break;

            case BEIDMessageType::AUTH_DATA :
                $msg = new BEIDMessageAuthenticationData($request);
                break;
            case BEIDMessageType::AUTH_REQUEST :
                $msg = new BEIDMessageAuthenticationRequest();
                break;
            default:
                throw new BEIDMessageException('Unknown message '.$type);
                break;
        }
        $msg->setProtocolVersion($version);
        return $msg;
    }
}
?>
