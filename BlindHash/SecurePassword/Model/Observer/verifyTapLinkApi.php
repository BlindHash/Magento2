<?php namespace BlindHash\SecurePassword\Model\Observer;

class verifyTapLinkApi implements \Magento\Framework\Event\ObserverInterface
{

    protected $scopeConfig;
    protected $encryptor;
    protected $resourceConfig;

    public function __construct(\Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig, \Magento\Framework\Encryption\EncryptorInterface $encryptor, \Magento\Framework\App\Config\ConfigResource\ConfigInterface $resourceConfig)
    {
        $this->scopeConfig = $scopeConfig;
        $this->encryptor = $encryptor;
        $this->resourceConfig = $resourceConfig;
    }

    public function execute(\Magento\Framework\Event\Observer $observer)
    {
        if (!$this->scopeConfig->getValue('blindhash/general/enabled')) {
            return;
        }

        $taplink = $this->encryptor->getTaplinkObject();
        $publicKey = $taplink->getPublicKey();
        
        // TODO encrypt test

        if ($publicKey) {
            $this->resourceConfig->saveConfig('blindhash/general/api_public_key', $publicKey, \Magento\Framework\App\Config\ScopeConfigInterface::SCOPE_TYPE_DEFAULT, \Magento\Store\Model\Store::DEFAULT_STORE_ID);
        }
    }
}
