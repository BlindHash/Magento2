<?php namespace BlindHash\SecurePassword\Model;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\Math\Random;

class Upgrade extends \BlindHash\SecurePassword\Model\Encryption
{

    protected $write;
    protected $customerPasswordTable;
    protected $adminPasswordTable;
    protected $prefix;
    protected $count = 0;

    const LIMIT = 100;

    public function __construct(\Magento\Framework\App\ResourceConnection $resource, Random $random, DeploymentConfig $deploymentConfig, \Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig)
    {
        $this->write = $resource->getConnection();
        $this->customerPasswordTable = $resource->getTableName('customer_entity');
        $this->adminPasswordTable = $resource->getTableName('admin_user');
        $this->prefix = self::PREFIX . self::BLINDHASH_DELIMITER;
        parent::__construct($random, $deploymentConfig, $scopeConfig);
    }

    /**
     * Upgrade all simple hashes to blind hashes
     * @return int
     */
    public function upgradeAllPasswords()
    {
        $this->upgradeAllAdminPasswords();
        $this->upgradeAllCustomerPasswords();
        return $this->count;
    }

    /**
     * Upgrade all simple hashes to blind hashes of admin users
     * @return int
     */
    protected function upgradeAllAdminPasswords()
    {
        $query = "SELECT user_id,password AS hash FROM {$this->adminPasswordTable} WHERE password NOT like '$this->prefix%' AND password <> ''";
        $passwordList = $this->write->fetchAll($query);

        if (!$passwordList)
            return;

        foreach ($passwordList as $password)
            $this->_convertToBlindHash($password['hash'], $password['user_id'], $this->adminPasswordTable, 'password', 'user_id');
    }

    /**
     * Upgrade all simple hashes to blind hashes of customers
     * @return int
     */
    protected function upgradeAllCustomerPasswords()
    {
        $limit = self::LIMIT;
        while (true) {

            $query = "SELECT entity_id,password_hash AS hash FROM {$this->customerPasswordTable} WHERE password_hash NOT like '$this->prefix%' AND password_hash <> '' limit {$limit}";
            $passwordList = $this->write->fetchAll($query);

            if (!$passwordList)
                break;

            foreach ($passwordList as $password)
                $this->_convertToBlindHash($password['hash'], $password['entity_id'], $this->customerPasswordTable, 'password_hash', 'entity_id');
        }
    }

    /**
     * Convert old hash to blind hash and save to DB
     * 
     * @param string $hash
     * @param int $id
     * @param string $table
     * @param string $field1
     * @param string $field2
     * @return void
     */
    protected function _convertToBlindHash($hash, $id, $table, $field1, $field2)
    {
        $hashUpdated = '';
        $hashArr = @explode(parent::DELIMITER, $hash);
        list($hash, $salt, $version) = $hashArr;
        $hashUpdated = $this->_blindhash($hash, $salt, $version);

        if (empty($hashUpdated))
            return;

        if ($this->write->update($table, array($field1 => $hashUpdated), array($field2 . ' = ?' => $id)))
            $this->count++;
    }
}
