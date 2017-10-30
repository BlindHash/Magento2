<?php namespace BlindHash\SecurePassword\Model;

class Hashes
{

    protected $resource;
    protected $read;
    protected $write;
    protected $customerPasswordTable;
    protected $adminPasswordTable;
    protected $apiPasswordTable;
    protected $attributeId;

    public function _construct()
    {
        
    }

    /**
     * Get Total Password Hashes Count
     * 
     * @return int
     */
    public function getTotalHashes()
    {
        $query = "SELECT SUM(total.hash) FROM (SELECT count(*) as hash FROM {$this->customerPasswordTable} WHERE attribute_id = {$this->attributeId} AND"
            . " value <> '' UNION ALL SELECT count(*) as hash FROM {$this->apiPasswordTable} WHERE `api_key` <> '' UNION ALL SELECT count(*) as hash FROM"
            . " {$this->adminPasswordTable} WHERE `password` <> '') as total";
        return $this->read->fetchOne($query);
    }

    /**
     * Get Total Blind Hash Protected Password Hashes Count
     * 
     * @return int
     */
    public function getTotalBlindHashes()
    {
        $blindhashPrefix = BlindHash_SecurePassword_Model_Encryption::PREFIX . BlindHash_SecurePassword_Model_Encryption::DELIMITER;
        $query = "SELECT SUM(total.hash) FROM (SELECT count(*) as hash FROM {$this->customerPasswordTable} WHERE attribute_id = {$this->attributeId} AND"
            . " value like '$blindhashPrefix%' UNION ALL SELECT count(*) as hash FROM {$this->apiPasswordTable} WHERE `api_key` like '$blindhashPrefix%'"
            . " UNION ALL SELECT count(*) as hash FROM {$this->adminPasswordTable} WHERE `password` like '$blindhashPrefix%') as total";

        return $this->read->fetchOne($query);
    }
}
