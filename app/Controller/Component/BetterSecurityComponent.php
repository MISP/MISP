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

    /**
     * The only method overrides CakeRequest acts on without discarding the
     * request body. Mirrors the list in CakeRequest::_processPost().
     */
    const ALLOWED_METHOD_OVERRIDES = array('POST', 'PUT', 'PATCH', 'DELETE');

    /**
     * Reject `_method` overrides that name anything but a write verb.
     *
     * CakeRequest::_processPost() honours a `_method` field in the POST body by
     * rewriting REQUEST_METHOD, and for any verb outside POST/PUT/PATCH/DELETE
     * it *also* empties $request->data. SecurityComponent::startup() then reads
     * $hasData as false and skips both _validatePost() and _validateCsrf(), so a
     * cross-site form posting nothing but `_method=GET` reaches any action that
     * takes its input from the URL with form security switched off entirely.
     *
     * MISP never emits a `_method` other than those four verbs, so anything else
     * is refused here - before parent::startup() computes $hasData from the
     * emptied body.
     *
     * @param Controller $controller
     * @return void
     * @throws BadRequestException
     */
    private function __rejectUnsafeMethodOverride(Controller $controller)
    {
        // Header first, then body - the same precedence _processPost() applies.
        $override = null;
        if (isset($_POST['_method'])) {
            $override = $_POST['_method'];
        }
        $headerOverride = env('HTTP_X_HTTP_METHOD_OVERRIDE');
        if (!empty($headerOverride)) {
            $override = $headerOverride;
        }
        if ($override === null) {
            return;
        }
        // A non-string override (`_method[]=GET`) misses Cake's in_array() check
        // just as surely as an unexpected verb does, so it is refused too.
        if (is_string($override) && in_array($override, self::ALLOWED_METHOD_OVERRIDES, true)) {
            return;
        }
        $this->log(sprintf(
            'Rejected unsupported HTTP method override when accessing %s (override: %s).',
            $controller->here,
            is_string($override) ? $override : gettype($override)
        ));
        throw new BadRequestException(__('Unsupported HTTP method override.'));
    }

    public function startup(Controller $controller)
    {
        $this->__rejectUnsafeMethodOverride($controller);
        return parent::startup($controller);
    }

    public function blackHole(Controller $controller, $error = '', SecurityException $exception = null)
    {
        $action = $controller->request->params['action'];
        $unlockedActions = JsonTool::encode($this->unlockedActions);
        $isRest = $controller->IndexFilter->isRest() ? '1' : '0';
        $this->log("Blackhole exception when accessing $controller->here (isRest: $isRest, action: $action, unlockedActions: $unlockedActions): {$exception->getMessage()}"); // log blackhole exception
        return parent::blackHole($controller, $error, $exception);
    }

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
     * Accept the CSRF token from the `X-CSRF-Token` header as well as from the
     * request body.
     *
     * Same-origin AJAX cannot use the body form: `Security` starts up before the
     * component that decodes a JSON request body, so `request->data('_Token.key')`
     * is empty for any caller posting `application/json`. A header carries the
     * token regardless of content type, and it is a strictly stronger position
     * than the body field to begin with - `X-CSRF-Token` is not CORS-safelisted,
     * so a cross-origin page cannot attach it without a preflight this instance
     * refuses unless `Security.allow_cors` names the origin.
     *
     * A header token is validated but not consumed, whatever `csrfUseOnce` says:
     * the page that rendered it has exactly one token and makes an unbounded
     * number of AJAX calls with it, so consuming it would break every call after
     * the first. It still expires with the page's token, so a page left open past
     * `csrfExpires` has to be reloaded - the same deal its forms already get.
     *
     * @param Controller $controller
     * @return bool
     * @throws SecurityException
     */
    protected function _validateCsrf(Controller $controller)
    {
        $headerToken = $controller->request->header('X-CSRF-Token');
        if (empty($headerToken)) {
            return parent::_validateCsrf($controller);
        }
        $token = $this->Session->read('_Token');
        if (!isset($token['csrfTokens'][$headerToken])) {
            throw new SecurityException('CSRF token mismatch');
        }
        if ($token['csrfTokens'][$headerToken] < time()) {
            throw new SecurityException('CSRF token expired');
        }
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
