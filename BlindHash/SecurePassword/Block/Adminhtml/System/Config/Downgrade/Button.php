<?php namespace BlindHash\SecurePassword\Block\Adminhtml\System\Config\Downgrade;

class Button extends \Magento\Config\Block\System\Config\Form\Field
{

    /**
     * Downgrade hash button along with needful js
     * 
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @return string
     */
    protected function _getElementHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element)
    {

        $url = $this->getUrl("blindhash/downgrade/hashes");
        $downgradeHashesJs = " <script type='text/javascript'>
            function downgradeHashes(){
            
                var privateKey = document.getElementById('blindhash_general_api_private_key'); 
                
                if(privateKey.value)
                    setLocation('{$url}?private_key='+privateKey.value);
                else
                    alert('Please provide private key in below input to downgrade hashes');
                }</script>";
        $button = $this->getLayout()->createBlock(
                'Magento\Backend\Block\Widget\Button'
            )->setData(
            [
                'id' => 'downgrade_hashes',
                'label' => __('Downgrade Hashes!'),
                'onclick' => __("downgradeHashes()"),
            ]
        );

        return $button->toHtml() . $downgradeHashesJs;
    }

    /**
     * Decorate field row html
     *
     * @param \Magento\Framework\Data\Form\Element\AbstractElement $element
     * @param string $html
     * @return string
     */
    protected function _decorateRowHtml(\Magento\Framework\Data\Form\Element\AbstractElement $element, $html)
    {
         $unInstallKey = '<tr id = "row_blindhash_general_api_private_key"><td class="label"><span data-config-scope="[STORE VIEW]">Uninstall Key</span></td>
        <td class = "value"><input id = "blindhash_general_api_private_key" class = " input-text" type = "text"></td>
        </tr>';

        return '<tr id="row_' . $element->getHtmlId() . '">' . $html . '</tr>' . $unInstallKey;
    }
}
