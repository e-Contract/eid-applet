<?php
/**
 * Placeholder for autoloader
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

 /** TODO replace with smart autoloader **/

require_once('beid/dao/BEIDAddress.php');
require_once('beid/dao/BEIDDocumentType.php');
require_once('beid/dao/BEIDIdentity.php');
require_once('beid/dao/BEIDIdentityException.php');

require_once('beid/helper/BEIDHelperConvert.php');
require_once('beid/helper/BEIDHelperException.php');
require_once('beid/helper/BEIDHelperLogger.php');
require_once('beid/helper/BEIDHelperTLV.php');

require_once('beid/message/BEIDMessage.php');
require_once('beid/message/BEIDMessageBadRequest.php');
require_once('beid/message/BEIDMessageAuthenticationData.php');
require_once('beid/message/BEIDMessageAuthenticationRequest.php');
require_once('beid/message/BEIDMessageException.php');
require_once('beid/message/BEIDMessageFactory.php');
require_once('beid/message/BEIDMessageFinished.php');
require_once('beid/message/BEIDMessageHeader.php');
require_once('beid/message/BEIDMessageHello.php');
require_once('beid/message/BEIDMessageIdentificationRequest.php');
require_once('beid/message/BEIDMessageIdentityData.php');
require_once('beid/message/BEIDMessageKiosk.php');
require_once('beid/message/BEIDMessageType.php');

require_once('beid/service/BEIDServiceAuthentication.php');
require_once('beid/service/BEIDServiceIdentity.php');

?>
