<?php namespace BlindHash\SecurePassword\Model\Observer;

class verifyTapLinkApi implements \Magento\Framework\Event\ObserverInterface
{

    protected $scopeConfig;
    protected $encryptor;
    protected $resourceConfig;
    protected $messageManager;

    public function __construct(\Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig, \Magento\Framework\Encryption\EncryptorInterface $encryptor, \Magento\Framework\App\Config\ConfigResource\ConfigInterface $resourceConfig, \Magento\Framework\Message\ManagerInterface $messageManager)
    {
        $this->scopeConfig = $scopeConfig;
        $this->encryptor = $encryptor;
        $this->resourceConfig = $resourceConfig;
        $this->messageManager = $messageManager;
    }

    /**
     * Verify Tap link App Id and store public key
     * 
     * @param \Magento\Framework\Event\Observer $observer
     * @return void
     */
    public function execute(\Magento\Framework\Event\Observer $observer)
    {
        if (empty($this->scopeConfig->getValue('blindhash/general/api_key')))
            return;

        if ($this->scopeConfig->getValue('blindhash/general/api_public_key'))
            return;


        $taplink = $this->encryptor->getTaplinkObject();
        $publicKey = $taplink->getPublicKey();
        $encryptTest = false;

        if (empty($publicKey)) {
            $this->resourceConfig->saveConfig('blindhash/general/enabled', '', \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
            $this->resourceConfig->saveConfig('blindhash/general/api_key', '', \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
            $this->resourceConfig->saveConfig('blindhash/general/api_public_key', '', \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);

            $this->resourceConfig->saveConfig('blindhash/general/encryption_available', false, \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
            $this->messageManager->addError(__('Api key is not valid.'));
            return;
        }

        $encryptTest = $taplink->encryptTest();
        $this->resourceConfig->saveConfig('blindhash/general/encryption_available', $encryptTest, \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);

        if ($encryptTest) {
            $this->resourceConfig->saveConfig('blindhash/general/api_public_key', $publicKey, \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
        } else {
            $this->resourceConfig->saveConfig('blindhash/general/enabled', '', \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
            $this->resourceConfig->saveConfig('blindhash/general/api_public_key', '', \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
        }
    }
}
