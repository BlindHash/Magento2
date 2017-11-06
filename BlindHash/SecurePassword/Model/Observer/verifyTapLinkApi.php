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

        $defaultScope = \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT;
        $defaultStoreId = \Magento\Store\Model\Store::DEFAULT_STORE_ID;

        $taplink = $this->encryptor->getTaplinkObject();

        if (!$taplink->verifyAppId()) {
            $this->resourceConfig->saveConfig('blindhash/general/enabled', '', $defaultScope, $defaultStoreId);
            $this->resourceConfig->saveConfig('blindhash/general/api_key', '', $defaultScope, $defaultStoreId);
            $this->resourceConfig->saveConfig('blindhash/general/api_public_key', '', $defaultScope, $defaultStoreId);

            $this->resourceConfig->saveConfig('blindhash/general/encryption_available', false, $defaultScope, $defaultStoreId);
            $this->messageManager->addError(__('Specified AppID is Invalid.'));
            return;
        }

        $encryptTest = $taplink->encryptTest();        
        $this->resourceConfig->saveConfig('blindhash/general/encryption_available', $encryptTest, $defaultScope, $defaultStoreId);
        
        $publicKey = $taplink->getPublicKey();
        
        if (empty($publicKey)) {
            $this->resourceConfig->saveConfig('blindhash/general/api_public_key', '', $defaultScope, $defaultStoreId);
        } else {
            $this->resourceConfig->saveConfig('blindhash/general/api_public_key', $publicKey, $defaultScope, $defaultStoreId);
        }
    }
}
