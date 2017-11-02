<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Total;

class Hashes extends \Magento\Config\Block\System\Config\Form\Field
{

    protected $hashes;

    public function __construct(\Magento\Backend\Block\Template\Context $context, \BlindHash\SecurePassword\Model\Hashes $hashes, array $data = [])
    {
        $this->hashes = $hashes;
        parent::__construct($context, $data);
    }

    /**
     * Return total hashes count
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return int
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {        
        return $this->hashes->getTotalHashes();
    }
}
