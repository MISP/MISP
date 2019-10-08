<?php

App::uses('RandomTool', 'Tools');
App::uses('Component', 'Controller');

class RateLimitComponent extends Component
{
    private $__limitedFunctions = array(
        'attributes' => array(
            'restSearch' => 1
        ),
        'events' => array(
            'restSearch' => 1
        )
    );

    public $components = array('RestResponse');

    public function check($user, $controller, $action, $Model, &$info = array(), $responseType)
    {
        if (!empty($user['Role']['enforce_rate_limit'])) {
            $uuid = Configure::read('MISP.uuid');
            if (empty($uuid)) {
                $uuid = 'no-uuid';
            }
            $keyName = 'misp:' . $uuid . ':rate_limit:' . $user['id'];
            if (!empty($this->__limitedFunctions[$controller][$action])) {
                if ($user['Role']['rate_limit_count'] == 0) {
                    throw new MethodNotAllowedException(__('API searches are not allowed for this user role.'));
                }
                $redis = $Model->setupRedis();
                $count = $redis->get($keyName);
                if ($count !== false && $count >= $user['Role']['rate_limit_count']) {
                    $info = array(
                        'limit' => $user['Role']['rate_limit_count'],
                        'reset' => $redis->ttl($keyName),
                        'remaining'=> $user['Role']['rate_limit_count'] - $count
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
                    'remaining'=> $user['Role']['rate_limit_count'] - $count
                );
            }
        }
        return true;
    }
}
