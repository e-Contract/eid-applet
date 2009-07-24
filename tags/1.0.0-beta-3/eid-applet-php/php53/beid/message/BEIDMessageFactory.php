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
            case BEIDMessageType::ID_DATA :
                $msg = new BEIDMessageIdentityData();

                $idSize = $request->getHeader(BEIDMessageHeader::ID_SIZE);
                $addressSize = $request->getHeader(BEIDMessageHeader::ADDRESS_SIZE);
                $photoSize = $request->getHeader(BEIDMessageHeader::PHOTO_SIZE);
                
                $msg->setIdentitySize(intval($idSize));
                $msg->setAddressSize(intval($addressSize));
                $msg->setPhotoSize(intval($photoSize));
                
                break;
            case BEIDMessageType::ID_REQUEST :
                $msg = new BEIDMessageIdentificationRequest();
                break;
            case BEIDMessageType::AUTH_DATA :
                $msg = new BEIDMessageAuthenticationData();

                $salt = $request->getHeader(BEIDMessageHeader::SALT_SIZE);
                $sig = $request->getHeader(BEIDMessageHeader::SIG_SIZE);
                
                $msg->setSaltSize(intval($salt));
                $msg->setSignatureSize(intval($sig));
                
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
