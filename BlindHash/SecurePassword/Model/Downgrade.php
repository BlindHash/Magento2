<?php namespace BlindHash\SecurePassword\Model;

use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\Math\Random;

class Downgrade extends \BlindHash\SecurePassword\Model\Encryption
{

    protected $write;
    protected $customerPasswordTable;
    protected $adminPasswordTable;
    protected $prefix;
    protected $privateKey;
    protected $publicKeyHex;
    protected $taplink;
    protected $messageManager;
    protected $count = 0;
    protected $_responseFactory;
    protected $_url;

    const LIMIT = 100;

    public function __construct(\Magento\Framework\App\ResourceConnection $resource, Random $random, DeploymentConfig $deploymentConfig, \Magento\Framework\App\Config\ScopeConfigInterface\Proxy $scopeConfig, \BlindHash\SecurePassword\Helper\Data $helper, \Magento\Framework\Message\ManagerInterface $messageManager, \Magento\Framework\App\ResponseFactory $responseFactory, \Magento\Framework\UrlInterface $url)
    {
        $this->write = $resource->getConnection();
        $this->customerPasswordTable = $resource->getTableName('customer_entity');
        $this->messageManager = $messageManager;
        $this->adminPasswordTable = $resource->getTableName('admin_user');
        $this->prefix = self::PREFIX . self::BLINDHASH_DELIMITER;
        $this->_responseFactory = $responseFactory;
        $this->_url = $url;
        parent::__construct($random, $deploymentConfig, $scopeConfig, $helper);
    }

    /**
     * Downgrade all blind hashes to simple magento hashes
     * @return int
     */
    public function downgradeAllPasswords($privateKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKeyHex = $this->getPublicKey();
        $this->taplink = $this->getTaplinkObject();
        $this->downgradeAllAdminPasswords();
        $this->downgradeAllCustomerPasswords();
        return $this->count;
    }

    /**
     * Downgrade all blind hashes of admin users
     * @return int
     */
    protected function downgradeAllAdminPasswords()
    {
        $query = "SELECT user_id,password AS hash FROM {$this->adminPasswordTable} WHERE password like '$this->prefix%' ";
        $passwordList = $this->write->fetchAll($query);

        if (!$passwordList)
            return;

        $count = 0;
        foreach ($passwordList as $password)
            $this->_convertToOldHash($password['hash'], $password['user_id'], $this->adminPasswordTable, 'password', 'user_id');
    }

    /**
     * Downgrade all blind hashes of customers
     * @return int
     */
    public function downgradeAllCustomerPasswords()
    {
        $limit = self::LIMIT;
        while (true) {

            $query = "SELECT entity_id,password_hash AS hash FROM {$this->customerPasswordTable} WHERE password_hash like '$this->prefix%' limit {$limit}";
            $passwordList = $this->write->fetchAll($query);

            if (!$passwordList)
                break;

            foreach ($passwordList as $password)
                $this->_convertToOldHash($password['hash'], $password['entity_id'], $this->customerPasswordTable, 'password_hash', 'entity_id');
        }
    }

    /**
     * Downgrade password from blindhash to old sha256 hash and update to DB
     * 
     * @param string $hash
     * @param int $id
     * @param string $table
     * @param string $field1
     * @param string $field2
     * @return void
     */
    protected function _convertToOldHash($hash, $id, $table, $field1, $field2)
    {
        $hashArr = explode(self::BLINDHASH_DELIMITER, $hash);
        if ((count($hashArr) < 5)) {
            return;
        }

        list($T, $expectedHash2Hex, $salt, $version, $hash1Encrypted) = $hashArr;

        $hash1 = $this->taplink->decrypt($this->publicKeyHex, $this->privateKey, $hash1Encrypted);

        // If decryption fails then get back to admin with error
        if ($hash1Encrypted && empty($hash1)) {
            $this->messageManager->addError(__('Not able to decrypt password.'));
            $url = $this->_url->getUrl('adminhtml/system_config/edit', array('section' => 'blindhash'));
            $this->_responseFactory->create()->setRedirect($url)->sendResponse();
            exit;
        }

        if ($version == self::NEW_HASHING_VERSION) {
            $version = self::HASH_VERSION_LATEST;
        }

        $hash1 = @implode(parent::DELIMITER, [$hash1, $salt, $version]);

        if ($this->write->update($table, array($field1 => $hash1), array($field2 . ' = ?' => $id)))
            $this->count++;
    }
}
