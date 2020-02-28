<?php namespace BlindHash\SecurePassword\Model;

require_once __DIR__ . '/Taplink/Client.php';
require_once __DIR__ . '/Taplink/Response.php';

use Client;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\Math\Random;

class Encryption extends \Magento\Framework\Encryption\Encryptor implements \Magento\Framework\Encryption\EncryptorInterface
{

    const BLINDHASH_SALT_LENGTH = 64;
    const HASH_ALGORITHM = 'sha512';
    const NEW_HASHING_VERSION = 3;
    const BLINDHASH_DELIMITER = '$';
    const PREFIX = 'T';

    protected $taplink;
    protected $scopeConfig;
    protected $helper;

    public function __construct(
    Random $random, DeploymentConfig $deploymentConfig, \Magento\Framework\App\Config\ScopeConfigInterface\Proxy $scopeConfig, \BlindHash\SecurePassword\Helper\Data $helper)
    {
        $this->scopeConfig = $scopeConfig;
        $this->helper = $helper;
        parent::__construct($random, $deploymentConfig);
    }

    public function getHash($password, $salt = false, $version = self::NEW_HASHING_VERSION)
    {

        if ($salt === false || !(boolean) $this->scopeConfig->getValue('blindhash/general/enabled')) {
            return parent::getHash($password, $salt, self::HASH_VERSION_LATEST);
        }

        if ($salt === true) {
            $salt = self::BLINDHASH_SALT_LENGTH;
        }
        if (is_integer($salt)) {
            $salt = $this->random->getRandomString($salt);
        }

        $taplink = $this->getTaplinkObject();
        $publicKey = $this->getPublicKey();

        // The hash to send to TapLink is the SHA512-HMAC(salt, password)
        $res = $taplink->newPassword(hash_hmac(self::HASH_ALGORITHM, $password, $salt));

        if ($res->err) {
            throw new \Exception($res->errMsg);
        }

        // Adding magento hash as last parameter
        $hash1 = @explode(self::DELIMITER, parent::getHash($password, $salt, $version))[0];

        if ((boolean) $this->scopeConfig->getValue('blindhash/general/legacy_hashes')) {
            // encrypt with libsodium
            $hash1 = $taplink->encrypt($publicKey, $hash1);
        }

        return implode(self::BLINDHASH_DELIMITER, [self::PREFIX, $res->hash2Hex, $salt, self::NEW_HASHING_VERSION, $hash1]);
    }

    protected function _blindhash($hash, $salt, $version = self::NEW_HASHING_VERSION)
    {
        $taplink = $this->getTaplinkObject();
        $publicKey = $this->getPublicKey();

        // The hash to send to TapLink is the SHA512-HMAC(salt, password)
        $res = $taplink->newPassword(hash_hmac(self::HASH_ALGORITHM, $hash, $salt));

        if ($res->err) {
            throw new \Exception($res->errMsg);
        }

        if ((boolean) $this->scopeConfig->getValue('blindhash/general/legacy_hashes')) {
            // encrypt with libsodium
            $hash = $taplink->encrypt($publicKey, $hash);
        }

        return @implode(self::BLINDHASH_DELIMITER, [self::PREFIX, $res->hash2Hex, $salt, $version, $hash]);
    }

    public function getTaplinkObject()
    {
        if ($this->taplink)
            return $this->taplink;

        if (!$this->scopeConfig->getValue('blindhash/general/api_key')) {
            return;
        }

        $appId = $this->scopeConfig->getValue('blindhash/general/api_key');
        $retryCount = $this->scopeConfig->getValue('blindhash/request/retry_count');
        $timeout = $this->scopeConfig->getValue('blindhash/request/timeout');
        $serverList = ($this->scopeConfig->getValue('blindhash/general/server_list')) ? @explode(',', $this->scopeConfig->getValue('blindhash/general/server_list')) : array();

        return $this->taplink = new Client($appId, $retryCount, $timeout, $serverList, $this->helper);
    }

    public function getPublicKey()
    {
        return $this->scopeConfig->getValue('blindhash/general/api_public_key');
    }

    public function isValidHash($password, $hash)
    {
        if (!$this->IsBlindHashed($hash)) {
            return parent::isValidHash($password, $hash);
        }

        // Get the pieces of the puzzle.
        list($T, $expectedHash2Hex, $salt, $version, $hash1) = explode(self::BLINDHASH_DELIMITER, $hash);

        $version = (int) $version;
        if ($version < self::NEW_HASHING_VERSION) {
            $password = @explode(self::DELIMITER, parent::getHash($password, $salt, $version))[0];
        }
        // This is a TapLink Blind hash
        $taplink = $this->getTaplinkObject();
        $res = $taplink->verifyPassword(hash_hmac(self::HASH_ALGORITHM, $password, $salt), $expectedHash2Hex);

        if ($res->err) {
            if ((substr($hash1, 0, 1) !== 'Z') && $version == self::NEW_HASHING_VERSION) {
                return parent::isValidHash($password, $hash1 . ":" . $salt . ":" . self::HASH_VERSION_LATEST);
            } else {
                Mage::logException($res->errMsg);
            }
        }

        return $res->matched;
    }

    public function IsBlindHashed($hash)
    {
        $hashArr = explode(self::BLINDHASH_DELIMITER, $hash);
        return (count($hashArr) > 4) ? true : false;
    }

    /**
     * Check if hash can be upgraded to a BlindHash
     * 
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public function CanUpgradeToBlindHash($password, $hash)
    {
        if ($this->IsBlindHashed($hash)) {
            return false;
        }

        return parent::isValidHash($password, $hash);
    }
}
