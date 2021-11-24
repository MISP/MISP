<?php
App::uses('SecurityComponent', 'Controller/Component');

/**
 * @property SessionComponent $Session
 */
class BetterSecurityComponent extends SecurityComponent
{
    /**
     * Do not generate CSRF token. This make sense for REST calls and for calls that do not use tokens. So session
     * will not be big with csrfLimit (by default 100) of token.
     * @var bool
     */
    public $doNotGenerateToken = false;

    public function generateToken(CakeRequest $request)
    {
        if (isset($request->params['requested']) && $request->params['requested'] === 1) {
            if ($this->Session->check('_Token')) {
                $request->params['_Token'] = $this->Session->read('_Token');
            }
            return false;
        }

        if ($this->doNotGenerateToken) {
            return true;
        }

        // No need to hash random data
        $authKey = bin2hex(Security::randomBytes(16));
        $token = array(
            'key' => $authKey,
            'allowedControllers' => $this->allowedControllers,
            'allowedActions' => $this->allowedActions,
            'unlockedFields' => array_merge($this->disabledFields, $this->unlockedFields),
            'csrfTokens' => array(),
        );

        if ($this->Session->check('_Token')) {
            $tokenData = $this->Session->read('_Token');
            if (!empty($tokenData['csrfTokens']) && is_array($tokenData['csrfTokens'])) {
                $token['csrfTokens'] = $this->_expireTokens($tokenData['csrfTokens']);
            }
        }
        if ($this->csrfUseOnce || empty($token['csrfTokens'])) {
            $token['csrfTokens'][$authKey] = strtotime($this->csrfExpires);
        }
        if (!$this->csrfUseOnce) {
            $csrfTokens = array_keys($token['csrfTokens']);
            $authKey = $csrfTokens[0];
            $token['key'] = $authKey;
            $token['csrfTokens'][$authKey] = strtotime($this->csrfExpires);
        }
        $this->Session->write('_Token', $token);
        $request->params['_Token'] = array(
            'key' => $token['key'],
            'unlockedFields' => $token['unlockedFields'],
        );
        return true;
    }

    /**
     * Avoid possible timing attacks by using `hash_equals` method to compare hashes.
     * @param Controller $controller
     * @return bool
     */
    protected function _validatePost(Controller $controller)
    {
        $token = $this->_validToken($controller);
        $hashParts = $this->_hashParts($controller);
        $check = sha1(implode('', $hashParts));

        if (hash_equals($token, $check)) {
            return true;
        }

        $msg = self::DEFAULT_EXCEPTION_MESSAGE;
        if (Configure::read('debug')) {
            $msg = $this->_debugPostTokenNotMatching($controller, $hashParts);
        }

        throw new AuthSecurityException($msg);
    }
}
