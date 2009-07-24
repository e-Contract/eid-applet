<?php
/**
 * Message type class
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageType {
    const HELLO = 'HelloMessage';
    const CLIENT_REQUEST = 'CheckClientMessage';
    const CLIENT_DATA = 'ClientEnvironmentMessage';
    const AUTH_REQUEST = 'AuthenticationRequestMessage';
    const AUTH_DATA = 'AuthenticationDataMessage';
    const ID_REQUEST = 'IdentificationRequestMessage';
    const ID_DATA = 'IdentityDataMessage';
    const KIOSK = 'KioskMessage';
    const BAD_REQUEST = 'BadRequest';
    const FINISHED = 'FinishedMessage';

}
?>
