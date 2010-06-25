<?php
/**
 * Citizen identity class, containing the citizen's name, address, photo etc
 *
 * More information on the content structure of the Belgian eID card can be found here:
 * @link http://www.snelbalie.be/downloads/Belgian_Electronic_Identity_Card_content_v2.2_NL.pdf
 * 
 * @package BEIDApplet-PHP5
 * @author Bart Hanssens
 * @copyright 2009, Fedict
 * @license http://www.gnu.org/licenses/lgpl-3.0.txt LGPL 3.0 license
 *
 * $Id$
 */

class BEIDIdentity {
    private $cardNumber;
    private $chipNumber;
    private $cardValidityDateBegin;
    private $cardValidityDateEnd;
    private $cardDeliveryMuncipality;
    private $nationalNumber;
    private $name;
    private $firstName;
    private $middleName;
    private $nationality;
    private $placeOfBirth;
    private $dateOfBirth;
    private $gender;
    private $nobleCondition;
    private $documentType;
    private $photoDigest;

    private $address;
    private $photo;

    const CARD_NUMBER = 1;
    const CHIP_NUMBER = 2;
    const CARD_VALIDITY_BEGIN = 3;
    const CARD_VALIDITY_END = 4;
    const CARD_DELIVERY_MUNICIPALITY = 5;
    const NATIONAL_NUMBER = 6;
    const NAME = 7;
    const FIRST_NAME = 8;
    const MIDDLE_NAME = 9;
    const NATIONALITY = 10;
    const PLACE_OF_BIRTH = 11;
    const DATE_OF_BIRTH = 12;
    const GENDER = 13;
    const NOBLE_CONDITION = 14;
    const DOCUMENT_TYPE = 15;
    const SPECIAL_STATUS =16;
    const PHOTO_DIGEST = 17;


    /**
     * Get the number of the eID card
     *
     * @return string the eID card number
     */
    public function getCardNumber() {
        return $this->cardNumber;
    }
    /**
     * Set the number of the eID card
     *
     * @param string $cardNumber a string of numbers
     */
    public function setCardNumber($cardNumber) {
        if (! is_string($cardNumber)) {
            return new BEIDException('Card number must be a string');
        }
        $this->cardNumber = $cardNumber;
    }

    /**
     * Get the chip number of the eID card, not to be confused with the card number
     *
     * @return string the eID card chip number
     */
    public function getChipNumber() {
        return $this->chipNumber;
    }
    /**
     * Set the chip number of the eID card
     *
     * @param string $chipNumber a string of numbers
     */
    public function setChipNumber($chipNumber) {
        if (! is_string($chipNumber)) {
            return new BEIDException('Chip number must be a string');
        }
        $this->chipNumber = $chipNumber;
    }

    /**
     * Get the begin date of the card validity
     *
     * @return DateTime
     */
    public function getCardValidityDateBegin() {
        return $this->cardValidityDateBegin;
    }
    /**
     * Set the begin date of the card validity
     *
     * @param DateTime $dateBegin
     * @return BEIDIdentityException
     */
    public function setCardValidityDateBegin(DateTime $dateBegin) {
        if (isset($this->cardValidityDateEnd)) {
            if ($this->cardValidityDateEnd < $dateBegin) {
                throw new BEIDIdentityException('Card validity date begin must be before card validity date end');
            }
        }
        $this->cardValidityDateBegin = $dateBegin;
    }

    /**
     * Get the end date of the card validity
     *
     * @return DateTime
     */
    public function getCardValidityDateEnd() {
        return $this->cardValidityDateEnd;
    }
    /**
     * Set the end date of the card validity (currently this is begin date + 5 years)
     * 
     * @param DateTime $dateEnd 
     * @return BEIDIdentityException
     */
    public function setCardValidityDateEnd(DateTime $dateEnd) {
        if (isset($this->cardValidityDateBegin)) {
            if ($this->cardValidityDateBegin > $dateEnd) {
                throw new BEIDIdentityException('Card validity date end must be after card validity date begin');
            }
        }
        $this->cardValidityDateEnd = $dateEnd;
    }

    /**
     * Get the (localized) name of the municipality that delivered the card to the citizen
     *
     * @return string name of the municipality
     */
    public function getCardDeliveryMunicipality() {
        return $this->cardDeliveryMuncipality;
    }
    /**
     * Set the name of the municipality that delivered the card to the citizen
     *
     * @param string $municipality
     */
    public function setCardDeliveryMunicipality($municipality) {
        if (! is_string($municipality)) {
            return new BEIDException('Municipality must be a string');
        }
        $this->cardDeliveryMuncipality = $municipality;
    }

    /**
     * Get the citizen's unique national number (RRN)
     *
     * Legal warning: using this numbere requires an official permit
     *
     * @return string
     */
    public function getNationalNumber() {
        return $this->nationalNumber;
    }
    /**
     * Set the citizen's unique national number (RRN)
     *
     * @param string $nationalNumber unique national number as a string
     */
    public function setNationalNumber($nationalNumber) {
        if (! is_string($nationalNumber)) {
            return new BEIDException('National number must be a string');
        }
        $this->nationalNumber = $nationalNumber;
    }

    /**
     * Get the citizen's first (two) name(s)
     * The firstname field on the eID may contain two first names
     *
     * @return string one or two first name(s)
     */
    public function getFirstName() {
        return $this->firstName;
    }
    /**
     * Set the citizen's first (two) name(s)
     *
     * @param string $firstName one of two first name(s)
     */
    public function setFirstName($firstName) {
        if (! is_string($firstName)) {
            return new BEIDException('First name must be a string');
        }
        $this->firstName = $firstName;
    }

    /**
     * Get the citizen's family name
     *
     * @return string family name
     */
    public function getName() {
        return $this->name;
    }
    /**
     * Set the citizen's family name
     *
     * @param string $name family name
     */
    public function setName($name) {
        if (! is_string($name)) {
            return new BEIDException('Name must be a string');
        }
        $this->name = $name;
    }

    /**
     * Get the first letter of the citizen's middle name
     *
     * @return string first letter of the middle name
     */
     public function getMiddleName() {
        return $this->middleName;
    }
    /**
     * Set the first letter of the citizen's middle name
     *
     * @param string $name middle name
     */
    public function setMiddleName($middleName) {
        if (! is_string($middleName)) {
            return new BEIDException('Middle name must be a string');
        }
        $this->middleName = $middleName;
    }

    /**
     * Get the (localized) name of nationality of the citizen.
     *
     * @return string nationality
     */
    public function getNationality() {
        return $this->nationality;
    }
     /**
     * Set the (localized) name of nationality of the citizen.
     *
     * @param string $nationality name of the nationality
     */
    public function setNationality($nationality) {
        if (! is_string($nationality)) {
            return new BEIDException('Nationality must be a string');
        }
        $this->nationality = $nationality;
    }

    /**
     * Get the (localized) name of the place/municipality where the citizen is born
     *
     * @return string
     */
    public function getPlaceOfBirth() {
        return $this->placeOfBirth;
    }
    /**
     * Set the (localized) name of the municipality where the citizen is born
     *
     * @param string $placeOfBirth
     */
    public function setPlaceOfBirth($placeOfBirth) {
        if (! is_string($placeOfBirth)) {
            return new BEIDException('Place of birth must be a string');
        }
        $this->placeOfBirth = $placeOfBirth;
    }

    /**
     * Get the date of birth of the citizen
     *
     * @return DateTime
     */
    public function getDateOfBirth() {
        return $this->dateOfBirth;
    }
    /**
     * Set the date of birth of the citizen
     *
     * @param DateTime $dateOfBirth
     */
    public function setDateOfBirth(DateTime $dateOfBirth) {
        $this->dateOfBirth = $dateOfBirth;
    }

    /**
     * Get the gender of the citizen
     *
     * @todo make a gender class
     * @return string letter indicating the gender
     */
    public function getGender() {
        return $this->gender;
    }
    /**
     * Set the gender of the citizen
     *
     * @param string $gender
     */
    public function setGender($gender) {
        if (! is_string($gender)) {
            return new BEIDException('Gender must be a string');
        }
        $this->gender = $gender;
    }

    /**
     * Get the noble condition
     *
     * @todo
     * @return string
     */
    public function getNobleCondition() {
        return $this->nobleCondition;
    }
    /**
     * Set the noble condition
     *
     * @param string $nobleCondition
     */
    public function setNobleCondition($nobleCondition) {
        $this->nobleCondition = $nobleCondition;
    }

    /**
     * Get the document type: eID card, kids-ID, ...
     *
     * @return BEIDDocument
     */
    public function getDocumentType() {
        return $this->documentType;
    }
    /**
     * Set the document type
     *
     * @param int $documentType
     */
    public function setDocumentType($documentType) {
        $this->documentType = $documentType;
    }

    /**
     * Get the SHA-1 hash of the citizen's photo
     *
     * @return bytes
     */
    public function getPhotoDigest() {
        return $this->photoDigest;
    }
    /**
     * Set the SHA-1 hash of the citizen's photo
     *
     * @param bytes $photoDigest
     */
    public function setPhotoDigest($photoDigest) {
        $this->photoDigest = $photoDigest;
    }

    /**
     * Get the citizen's current address
     *
     * Note that you have to explicitely ask the applet to provide this info
     * @see BEIDMessageIdentificationRequest::setIncludeAddress()
     *
     * @return BEIDAddress
     */
    public function getAddress() {
        return $this->address;
    }
    /**
     * Set the citizen's current address
     *
     * @param BEIDAddress $address
     */
    public function setAddress(BEIDAddress $address) {
        $this->address = $address;
    }

    /**
     * Get the citizen's photo as a raw JPEG bytestream
     *
     * Note that you have to explicitely ask the applet to provide this photo
     * @see BEIDMessageIdentificationRequest::setIncludePhoto()
     *
     * @todo make it a GD class ?
     * @return bytes
     */
    public function getPhoto() {
        return $this->photo;
    }
    /**
     * Set the citizen's photo
     *
     * @param bytes $photo
     */
    public function setPhoto($photo) {
        $this->photo = $photo;
    }

    /**
     * "Magic" PHP convenience method
     *
     * @return string
     */
    public function __toString() {
        return "$this->firstName $this->name ($this->placeOfBirth)";
    }
}
?>
