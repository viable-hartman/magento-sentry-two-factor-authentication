<?php

require_once(Mage::getBaseDir('lib') . DS . 'PhpUserAgent' . DS . 'UserAgentParser.php');

class HE_TwoFactorAuth_Helper_Trusted extends Mage_Core_Helper_Abstract
{
    public function getUserAgent()
    {
        $browser = parse_user_agent();
        return $browser['platform'] . ' ' . $browser['browser'];
    }

    public function getIpAddress()
    {
        $ip = Mage::helper('core/http')->getRemoteAddr();
        // In case of X-Forwarded-For.
        $ips = explode(',', $ip);
        return reset($ips);
    }

    public function getToken()
    {
        return sha1(uniqid(time()));
    }

    public function isTrustedDevicesEnabled()
    {
        return Mage::getStoreConfig('he2faconfig/control/trusted_device');
    }

    public function getTrustedTime() {
        return Mage::getStoreConfig('he2faconfig/control/trusted_device_duration');
    }
}

?>
