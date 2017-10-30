<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Total;

class Hashes extends \Magento\Config\Block\System\Config\Form\Field
{
    /**
     * Return total hashes count
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return int
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {
        // TODO return total hashes
        return "No of Hashes";
    }
}
