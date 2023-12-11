<?php
App::uses('Component', 'Controller');

class RateLimitComponent extends Component
{
    const LIMITED_FUNCTIONS = array(
        'attributes' => array(
            'restSearch' => 1
        ),
        'events' => array(
            'restSearch' => 1
        )
    );

    public $components = array('RestResponse');

    /**
     * @param array $user
     * @param string $controller
     * @param string $action
     * @param array $info
     * @param string $responseType
     * @return bool
     * @throws RedisException
     */
    public function check(array $user, $controller, $action, &$info = array(), $responseType)
    {
        if (!empty($user['Role']['enforce_rate_limit']) && isset(self::LIMITED_FUNCTIONS[$controller][$action])) {
            if ($user['Role']['rate_limit_count'] == 0) {
                throw new MethodNotAllowedException(__('API searches are not allowed for this user role.'));
            }
            try {
                $redis = RedisTool::init();
            } catch (Exception $e) {
                return true; // redis is not available, allow access
            }
            $uuid = Configure::read('MISP.uuid') ?: 'no-uuid';
            $keyName = 'misp:' . $uuid . ':rate_limit:' . $user['id'];
            $count = $redis->get($keyName);
            if ($count !== false && $count >= $user['Role']['rate_limit_count']) {
                $info = array(
                    'limit' => $user['Role']['rate_limit_count'],
                    'reset' => $redis->ttl($keyName),
                    'remaining' => $user['Role']['rate_limit_count'] - $count,
                );
                return $this->RestResponse->throwException(
                    429,
                    __('Rate limit exceeded.'),
                    '/' . $controller . '/' . $action,
                    $responseType
                );
            } else {
                if ($count === false) {
                    $redis->setEx($keyName, 900, 1);
                } else {
                    $redis->setEx($keyName, $redis->ttl($keyName), intval($count) + 1);
                }
            }
            $count += 1;
            $info = array(
                'limit' => $user['Role']['rate_limit_count'],
                'reset' => $redis->ttl($keyName),
                'remaining' => $user['Role']['rate_limit_count'] - $count
            );

        }
        return true;
    }
}
