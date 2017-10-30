<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Encryption;

class Available extends \Magento\Config\Block\System\Config\Form\Field
{

    /**
     * Encryption value show Yes/No based on boolean
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        return ($element->getValue()) ? "Yes" : "No";
    }
}
