<?php
namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Api;

class Publickey extends \Magento\Config\Block\System\Config\Form\Field
{
    /**
     * Disable public key inupt so it can not be updated
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        $element->setDisabled('disabled');
        return $element->getElementHtml();
    }
}
