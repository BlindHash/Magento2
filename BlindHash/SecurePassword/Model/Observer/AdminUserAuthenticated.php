<?php namespace BlindHash\SecurePassword\Model\Observer;

class AdminUserAuthenticated implements \Magento\Framework\Event\ObserverInterface
{

    protected $scopeConfig;
    protected $encryptor;

    public function __construct(\Magento\Framework\App\Config\ScopeConfigInterface $scopeConfig, \Magento\Framework\Encryption\EncryptorInterface $encryptor)
    {
        $this->scopeConfig = $scopeConfig;
        $this->encryptor = $encryptor;
    }

    /**
     * If the admin's password is not blind hashed then
     * replace it with new blind hash.
     * 
     * @param \Magento\Framework\Event\Observer $observer
     * @return void
     */
    public function execute(\Magento\Framework\Event\Observer $observer)
    {
        if (!(boolean) $this->scopeConfig->getValue('blindhash/general/enabled')) {
            return;
        }

        $password = $observer->getPassword();
        $user = $observer->getUser();
        if ($this->encryptor->CanUpgradeToBlindHash($password, $user->getPassword())
        ) {
            $user->setPassword($password);
            $user->save();
        }
    }
}
