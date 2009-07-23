<?php
/**
 * Identity data message
 *
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDMessageIdentityData extends BEIDMessage {
    private $sizeIdentity;
    private $sizeAddress;
    private $sizePhoto;


    /**
     * Get the size of the citizen's identity info (data sent by the applet)
     *
     * @return int
     */
    public function getIdentitySize() {
        return $this->sizeIdentity;
    }
    /**
     * Set the size of the identity info
     *
     * @param int $sizeIdentity
     */
    public function setIdentitySize($sizeIdentity) {
        if (! is_int($sizeIdentity)) {
            throw new BEIDMessageException('Size for identity must be integer');
        }
        if ($sizeIdentity < 0) {
            throw new BEIDMessageException('Size for identity must >= 0');
        }
        $this->sizeIdentity = $sizeIdentity;
    }

    /**
     * Get the size of the (zero-padded) citizen's address
     *
     * @return int
     */
    public function getAddressSize() {
        return $this->sizeAddress;
    }
    /**
     * Set the size of the citizen's address info
     *
     * @param int $sizeAddress
     */
    public function setAddressSize($sizeAddress) {
        if (! is_int($sizeAddress)) {
            throw new BEIDMessageException('Size for address must be integer');
        }
        if ($sizeAddress < 0) {
            throw new BEIDMessageException('Size for address must >= 0');
        }
        $this->sizeAddress = $sizeAddress;
    }

    /**
     * Get the size of the photo
     *
     * @return int
     */

    public function getPhotoSize() {
        return $this->sizePhoto;
    }
    /**
     * Set the size of the photo
     *
     * @param int $sizePhoto
     */
    public function setPhotoSize($sizePhoto) {
        if (! is_int($sizePhoto)) {
            throw new BEIDMessageException('Size for photo must be integer');
        }
        if ($sizePhoto < 0) {
            throw new BEIDMessageException('Size for photo must >= 0');
        }
        $this->sizePhoto = $sizePhoto;
    }


    /**
     * Get the identity info
     *
     * @return BEIDIdentity
     * @todo save photo
     */
    public function getIdentity() {
        $stream = HttpResponse::getRequestBodyStream();
        $identity = new BEIDIdentity();

        unset($_SESSION['Identity']);
        $end = $this->getIdentitySize();

        while (!feof($stream) && (ftell($stream) < $end)) {
            $tlv = BEIDHelperTLV::createFromStream($stream);
            $buffer = $tlv->getValue();

            /* TODO: sequence ? */
            switch($tlv->getTag()) {
                case BEIDIdentity::CARD_NUMBER :
                    $cardNumber = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setCardNumber($cardNumber);
                    break;
                case BEIDIdentity::CHIP_NUMBER :
                    $chipNumber = BEIDHelperConvert::bytesAsHexString($buffer);
                    $identity->setChipNumber($chipNumber);
                    break;
                case BEIDIdentity::CARD_VALIDITY_BEGIN :
                    $valBegin = BEIDHelperConvert::bytesAsDate($buffer);
                    $identity->setCardValidityDateBegin($valBegin);
                    break;
                case BEIDIdentity::CARD_VALIDITY_END :
                    $valEnd = BEIDHelperConvert::bytesAsDate($buffer);
                    $identity->setCardValidityDateEnd($valEnd);
                    break;
                case BEIDIdentity::CARD_DELIVERY_MUNICIPALITY :
                    $municipality = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setCardDeliveryMunicipality($municipality);
                    break;
                case BEIDIdentity::NATIONAL_NUMBER :
                    $national = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setNationalNumber($national);
                    break;
                case BEIDIdentity::NAME :
                    $name = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setName($name);
                    break;
                case BEIDIdentity::FIRST_NAME :
                    $firstName = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setFirstName($firstName);
                    break;
                case BEIDIdentity::MIDDLE_NAME :
                    $middleName = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setMiddleName($middleName);
                    break;
                case BEIDIdentity::NATIONALITY :
                    $nationality = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setNationality($nationality);
                    break;
                case BEIDIdentity::PLACE_OF_BIRTH :
                    $place = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setPlaceOfBirth($place);
                    break;
                case BEIDIdentity::DATE_OF_BIRTH :
                    $birth = BEIDHelperConvert::bytesAsDateFromText($buffer);
                    $identity->setDateOfBirth($birth);
                    break;
                case BEIDIdentity::GENDER :
                    $gender = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setGender($gender);
                    break;
                case BEIDIdentity::NOBLE_CONDITION :
                    $noble = BEIDHelperConvert::bytesAsString($buffer);
                    $identity->setNobleCondition($buffer);
                    break;
                case BEIDIdentity::DOCUMENT_TYPE :
                    $document = BEIDHelperConvert::byteAsInt($buffer);
                    $identity->setDocumentType(document);
                    break;
                case BEIDIdentity::SPECIAL_STATUS :
                    break;
                case BEIDIdentity::PHOTO_DIGEST :
                    $digest = BEIDHelperConvert::bytesAsHexString($buffer);
                    $identity->setPhotoDigest($digest);
                    break;
                case 0:
                    // end of tags;
                    break;
                default:
                    BEIDHelperLogger::logger('Unknown ID TLV tag:'.$tlv->getTag());
                    break;
            }
        }

        $end = ftell($stream) + $this->getAddressSize(); /* end of address */
        $address = new BEIDAddress();

        while (!feof($stream) && (ftell($stream) < $end)) {
            $tlv = BEIDHelperTLV::createFromStream($stream);
            $buffer = $tlv->getValue();

            switch ($tlv->getTag()) {
                case BEIDAddress::STREET_NUMBER :
                    $streetNumber = BEIDHelperConvert::bytesAsString($buffer);
                    $address->setStreetAndNumber($streetNumber);
                    break;
                case BEIDAddress::ZIP :
                    $zip = BEIDHelperConvert::bytesAsString($buffer);
                    $address->setZip($zip);
                    break;
                case BEIDAddress::MUNICIPALITY :
                    $municipality = BEIDHelperConvert::bytesAsString($buffer);
                    $address->setMunicipality($municipality);
                    break;
                case 0: /* end of useful address info, rest is zero-padded */
                    fseek($end);
                    break;
                default:
                    BEIDHelperLogger::logger('Unknown address TLV tag:'.$tlv->getTag());
                    break;
            }
        }
        $identity->setAddress($address);
        $_SESSION['Identity'] = $identity;

        return $identity;
    }


    public function __construct() {
        parent::__construct();
        $this->setProtocolType(BEIDMessageType::ID_DATA);
    }
}
?>
