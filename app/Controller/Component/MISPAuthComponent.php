<?php

App::uses('AuthComponent', 'Controller/Component');
/*
 * Customisable authentication component
 *
 * The standard authentication flow is handled by the
 * CakePHP AuthComponent. Here, we also provide the facility
 * to offer an alternative login mechanism provided by
 * a plugin. It is necessary to provide a custom
 * AuthComponent so that custom login views can be
 * implemented.
 *
 */
class MISPAuthComponent extends AuthComponent {

    /*
     * Initializes the custom AuthComponent
     *
     * Optionally modify the standard behaviour
     * according to configured plugins
     *
     * @param Controller the current controller
     *
     */
    public function initialize(Controller $controller) {
        if ($this->_isLinOTPAuthEnabled()) {
            // Override the standard login action to redirect
            // to LinOTP plugin's login page
            $this->loginAction = array(
                'plugin' => Inflector::underscore('LinOTPAuth'),
                'controller' => 'Login',
                'action' => 'index',
            );
        }

        parent::initialize($controller);
    }


    /*
    * Returns true if the LinOTPAuth Plugin is enabled and configured
    * @return true|false
    */
    private function _isLinOTPAuthEnabled()
    {
        $auth = Configure::read('Security.auth');
        $config = Configure::read('LinOTPAuth');

        // If both the Security.Auth and the LinOTPAuth configuration exists the return value depends on the fact
        // if the module is part of the list of authentication components.
        return $auth !== null && $config !== null && array_search("LinOTPAuth.LinOTP", $auth) !== false;
    }
}
