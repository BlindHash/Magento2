<?php namespace BlindHash\SecurePassword\Model;

class Hashes
{

    protected $read;
    protected $customerPasswordTable;
    protected $adminPasswordTable;

    public function __construct(\Magento\Framework\App\ResourceConnection $resource)
    {
        $this->read = $resource->getConnection();
        $this->customerPasswordTable = $resource->getTableName('customer_entity');
        $this->adminPasswordTable = $resource->getTableName('admin_user');
    }

    /**
     * Get Total Password Hashes Count
     * 
     * @return int
     */
    public function getTotalHashes()
    {
        $query = "SELECT SUM(total.hash) FROM (SELECT count(*) as hash FROM {$this->customerPasswordTable} WHERE password_hash <> '' "
            . "UNION ALL SELECT count(*) as hash FROM {$this->adminPasswordTable} WHERE `password` <> '') as total";
        return $this->read->fetchOne($query);
    }

    /**
     * Get Total Blind Hash Protected Password Hashes Count
     * 
     * @return int
     */
    public function getTotalBlindHashes()
    {
        $blindhashPrefix = \BlindHash\SecurePassword\Model\Encryption::PREFIX . \BlindHash\SecurePassword\Model\Encryption::BLINDHASH_DELIMITER;

        $query = "SELECT SUM(total.hash) FROM (SELECT count(*) as hash FROM {$this->customerPasswordTable} WHERE password_hash like '$blindhashPrefix%' "
            . "UNION ALL SELECT count(*) as hash FROM {$this->adminPasswordTable} WHERE `password` like '$blindhashPrefix%') as total";

        return $this->read->fetchOne($query);
    }
}
