<?php

/*
 * Author   : Greg Croasdill
 *            Human Element, Inc http://www.human-element.com
 *
 * License  : GPL  -- https://www.gnu.org/copyleft/gpl.html
 *
 * Observer watches login attempts (currently admin only) and will enforce multi-factor
 * authentication if not disabled.
 *
 * For more information on Duo security's API, please see -
 *   https://www.duosecurity.com
 */

class HE_TwoFactorAuth_Model_Observer
{
    protected $_allowedActions = array('login', 'forgotpassword', 'resetpassword', 'resetpasswordpost');

    public function __construct()
    {
        $this->_shouldLog = Mage::helper('he_twofactorauth')->shouldLog();
    }

    public function admin_user_authenticate_after($observer)
    {
        if (Mage::helper('he_twofactorauth')->isDisabled()) {
            return;
        }

        // check ip-whitelist
        if (Mage::helper('he_twofactorauth')->inWhitelist( Mage::helper('core/http')->getRemoteAddr() )) { 
            Mage::getSingleton('admin/session')->set2faState(HE_TwoFactorAuth_Model_Validate::TFA_STATE_ACTIVE);
        }

        if (Mage::getSingleton('admin/session')->get2faState() != HE_TwoFactorAuth_Model_Validate::TFA_STATE_ACTIVE) {

            if ($this->_shouldLog) {
                Mage::log("authenticate_after - get2faState is not active", 0, "two_factor_auth.log");
            }

            // set we are processing 2f login
            Mage::getSingleton('admin/session')->set2faState(HE_TwoFactorAuth_Model_Validate::TFA_STATE_PROCESSING);

            $provider = Mage::helper('he_twofactorauth/data')->getProvider();

            //redirect to the 2f login page
            $twoFactAuthPage = Mage::helper("adminhtml")->getUrl("adminhtml/twofactor/$provider");

            if ($this->_shouldLog) {
                Mage::log("authenticate_after - redirect to $twoFactAuthPage", 0, "two_factor_auth.log");
            }

            Mage::app()->getResponse()
                ->setRedirect($twoFactAuthPage)
                ->sendResponse();
            exit();
        } else {
            if ($this->_shouldLog) {
                Mage::log("authenticate_after - getValid2Fa is true", 0, "two_factor_auth.log");
            }
        }
    }

    /***
     * controller to check for valid 2fa
     * admin states
     *
     * @param $observer
     */

    public function check_twofactor_active($observer)
    {
        if (Mage::helper('he_twofactorauth')->isDisabled()) {
            return;
        }

        $request = $observer->getControllerAction()->getRequest();
        $tfaState = Mage::getSingleton('admin/session')->get2faState();
        $action = Mage::app()->getRequest()->getActionName();

        switch ($tfaState) {
            case HE_TwoFactorAuth_Model_Validate::TFA_STATE_NONE:
                if ($this->_shouldLog) {
                    Mage::log("check_twofactor_active - tfa state none", 0, "two_factor_auth.log");
                }
                break;
            case HE_TwoFactorAuth_Model_Validate::TFA_STATE_PROCESSING:
                if ($this->_shouldLog) {
                    Mage::log("check_twofactor_active - tfa state processing", 0, "two_factor_auth.log");
                }
                break;
            case HE_TwoFactorAuth_Model_Validate::TFA_STATE_ACTIVE:
                if ($this->_shouldLog) {
                    Mage::log("check_twofactor_active - tfa state active", 0, "two_factor_auth.log");
                }
                break;
            default:
                if ($this->_shouldLog) {
                    Mage::log("check_twofactor_active - tfa state unknown - " . $tfaState, 0, "two_factor_auth.log");
                }
        }

        if ($action == 'logout') {
            if ($this->_shouldLog) {
                Mage::log("check_twofactor_active - logout", 0, "two_factor_auth.log");
            }
            Mage::getSingleton('admin/session')->set2faState(HE_TwoFactorAuth_Model_Validate::TFA_STATE_NONE);

            return $this;
        }

        if (in_array($action, $this->_allowedActions)) {
            return $this;
        }

        if ($request->getControllerName() == 'twofactor'
            || $tfaState == HE_TwoFactorAuth_Model_Validate::TFA_STATE_ACTIVE
        ) {
            if ($this->_shouldLog) {
                Mage::log(
                    "check_twofactor_active - return controller twofactor or is active", 0, "two_factor_auth.log"
                );
            }

            return $this;
        }

        if (Mage::getSingleton('admin/session')->get2faState() != HE_TwoFactorAuth_Model_Validate::TFA_STATE_ACTIVE) {

            if ($this->_shouldLog) {
                Mage::log("check_twofactor_active - not active, try again", 0, "two_factor_auth.log");
            }

            $msg = Mage::helper('he_twofactorauth')->__(
                'You must complete Two Factor Authentication before accessing Magento administration'
            );
            Mage::getSingleton('adminhtml/session')->addError($msg);

            // set we are processing 2f login
            Mage::getSingleton('admin/session')->set2faState(HE_TwoFactorAuth_Model_Validate::TFA_STATE_PROCESSING);

            $provider = Mage::helper('he_twofactorauth')->getProvider();
            $twoFactAuthPage = Mage::helper("adminhtml")->getUrl("adminhtml/twofactor/$provider");

            //disable the dispatch for now
            $request = Mage::app()->getRequest();
            $action = $request->getActionName();
            Mage::app()->getFrontController()
                ->getAction()
                ->setFlag($action, Mage_Core_Controller_Varien_Action::FLAG_NO_DISPATCH, true);

            $response = Mage::app()->getResponse();

            if ($this->_shouldLog) {
                Mage::log("check_twofactor_active - redirect to $twoFactAuthPage", 0, "two_factor_auth.log");
            }

            $response->setRedirect($twoFactAuthPage)->sendResponse();
            exit();
        }
    }

    /* 
     * Add a fieldset and field to the admin edit user form
     * in order to allow selective clearing of a users shared secret (google)
     */

    public function googleClearSecretCheck(Varien_Event_Observer $observer)
    {
        $block = $observer->getEvent()->getBlock();

        if (!isset($block)) {
            return $this;
        }

        if ($block->getType() == 'adminhtml/permissions_user_edit_form') {

            // check that google is set for twofactor authentication            
            if (Mage::helper('he_twofactorauth')->getProvider() == 'google') {
                //create new custom fieldset 'website'
                $form = $block->getForm();
                $fieldset = $form->addFieldset(
                    'website_field', array(
                                       'legend' => 'Google Authenticator',
                                       'class'  => 'fieldset-wide'
                                   )
                );

                $fieldset->addField(
                    'checkbox', 'checkbox', array(
                                  'label'              => Mage::helper('he_twofactorauth')->__(
                                      'Reset Google Authenticator'
                                  ),
                                  'name'               => 'clear_google_secret',
                                  'checked'            => false,
                                  'onclick'            => "",
                                  'onchange'           => "",
                                  'value'              => '1',
                                  'disabled'           => false,
                                  'after_element_html' => '<small>Check this and save to reset this user\'s Google Authenticator.<br />They will need to use the QR code to reconnect their device after their next successful login.</small>',
                                  'tabindex'           => 1
                              )
                );
            }
        }
    }


    /*
     * Clear a user's google secret field if request
     *
     */
    public function googleSaveClear(Varien_Event_Observer $observer)
    {
        // check that a user record has been saved

        // if google is turned and 2fa active...
        if (Mage::helper('he_twofactorauth')->getProvider() == 'google') {
            $params = Mage::app()->getRequest()->getParams();
            if (isset($params['clear_google_secret'])) {
                if ($params['clear_google_secret'] == 1) {
                    $object = $observer->getEvent()->getObject();
                    $object->setTwofactorGoogleSecret(''); // just clear the secret

                    Mage::log(
                        "Clearing google secret for admin user (" . $object->getUsername() . ")", 0,
                        "two_factor_auth.log"
                    );
                }
            }
        }
    }

    protected function _getLoginCreds($observer, $result = false)
    {
        $username = $observer->getUserName();
        $user = Mage::getModel('admin/user')->loadByUsername($username);
        $password = $user->getPassword();
        $observer->getEvent()->setUser($user);
        $observer->getEvent()->setPassword($password);
        $result = $result ? 1 : 0;
        $observer->getEvent()->setResult($result);
        return $observer;
    }

    protected function _setPasswordData($observer)
    {
        /*
            Ideally, the PCI observer method adminAuthenticate looks for the plain text password to be provided
            Since, this controller action does not carry the plain text password, we are forced to provide the hashed password
            Magento, thinks the hash is a new password and hashes the hash again.
            This causes an invalid password error.
            We perform an update query to reset this password to the admin_user.
        */
        $user = $observer->getEvent()->getUser();
        /*
            For a user, if the original data of password is set and the current password is null,
            magento automatically sets the original data as the password
        */
        $password = $observer->getEvent()->getPassword();
        $user->setOrigData('password', $password);
        /*
         *  Add version compare to handle the different _beforeSave functionality in
         *  Mage_Admin_Model_user.
         *  In versions below 1.14.1.0, setPassword will assign the admin password to NULL,
         *  therefore only allowing the admin user login once.
         *  Checking for Enterprise occurs in the callAdminAuthenticate function
         */
        if (version_compare(Mage::getVersion(), '1.14.1.0', '>=')) {
            $user->setPassword();
        } else {
            $user->setPassword($password);
        }
        $user->save();
    }

    protected function _forceAdminUserLogout()
    {
        $adminSession = Mage::getSingleton('admin/session');
        if ($adminSession->isLoggedIn()) {
            // log out a locked user
            $adminSession->unsetAll();
            $adminSession->getCookie()->delete($adminSession->getSessionName());
        }
    }

    public function callAdminAuthenticate($observer)
    {
        if (Mage::getEdition() != "Enterprise") {
            return;
        }

        if ($observer->getEvent()->getName() == "admin_session_user_login_failed") {
            // for a failed login attempt, we get the username to update lock expiration
            $observer = $this->_getLoginCreds($observer);
        }

        try {
            Mage::getModel('enterprise_pci/observer')->adminAuthenticate($observer);
        } catch(Exception $e) {
            if ($e->getMessage() == Mage::helper('core')->__('This account is locked.')) {
            } else {
                Mage::logException($e);
            }
            // If an admin is logged in and the user is locked, we force a logout action
            $this->_forceAdminUserLogout();
            $lockInfo = $observer->getEvent()->getLockInfo();
            if ($lockInfo) {
                // update lock info value, for the event dispatching controller to display error message
                $lockInfo->setData("is_locked", true);
            }
            return $this;
        }

        if ($observer->getEvent()->getName() == "admin_session_user_login_failed") {
            return;
        }

        $this->_setPasswordData($observer);
        // for some reason, the failure_num first_failure and lock_expires values are not reset on a successful login
        $resource = Mage::getResourceSingleton('enterprise_pci/admin_user');
        $resource->unlock($observer->getEvent()->getUser()->getId());
        return;
    }
}
