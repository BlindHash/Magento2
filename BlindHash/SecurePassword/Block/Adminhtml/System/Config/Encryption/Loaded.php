<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Encryption;

class Loaded extends \Magento\Config\Block\System\Config\Form\Field
{

    /**
     * Encryption loaded label based on public key
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        return ($element->getValue()) ? "Loaded" : "Not Loaded";
    }
}
