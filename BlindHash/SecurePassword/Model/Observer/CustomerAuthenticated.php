<?php namespace BlindHash\SecurePassword\Model\Observer;

class CustomerAuthenticated implements \Magento\Framework\Event\ObserverInterface
{

    protected $scopeConfig;
    protected $encryptor;

    public function __construct(\Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig, \Magento\Framework\Encryption\EncryptorInterface $encryptor)
    {
        $this->scopeConfig = $scopeConfig;
        $this->encryptor = $encryptor;
    }

    /**
     * If the customer's password is not blind hashed then
     * replace it with new blind hash.
     * 
     * @param \Magento\Framework\Event\Observer $observer
     * @return void
     */
    public function execute(\Magento\Framework\Event\Observer $observer)
    {
        if (!$this->scopeConfig->getValue('blindhash/general/enabled')) {
            return;
        }

        $password = $observer->getPassword();
        $customer = $observer->getModel();

        if (!$this->encryptor->IsBlindHashed($customer->getPasswordHash())
        ) {
            $customer->setPassword($password);
            $customer->save();
        }
    }
}
