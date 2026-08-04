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

    /**
     * @param array $user
     * @param string $controller
     * @param string $action
     * @return array|null
     * @throws RedisException
     */
    public function check(array $user, $controller, $action)
    {
        if (!isset(self::LIMITED_FUNCTIONS[$controller][$action])) {
            return null; // no limit enforced for this controller action
        }

        if (empty($user['Role']['enforce_rate_limit'])) {
            return null; // no limit enforced for this role
        }

        $rateLimit = (int)$user['Role']['rate_limit_count'];
        if ($rateLimit === 0) {
            throw new MethodNotAllowedException(__('API searches are not allowed for this user role.'));
        }

        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return null; // redis is not available, allow access
        }

        $uuid = Configure::read('MISP.uuid') ?: 'no-uuid';
        $keyName = 'misp:' . $uuid . ':rate_limit:' . $user['id'];
        $count = $redis->get($keyName);

        if ($count !== false && $count >= $rateLimit) {
            return [
                'exceeded' => true,
                'limit' => $rateLimit,
                'reset' => $redis->ttl($keyName),
                'remaining' => $rateLimit - $count,
            ];
        }

        $newCount = $redis->incr($keyName);
        if ($newCount === 1) {
            $redis->expire($keyName, 900);
            $reset = 900;
        } else {
            $reset = $redis->ttl($keyName);
        }

        return [
            'exceeded' => false,
            'limit' => $rateLimit,
            'reset' => $reset,
            'remaining' => $rateLimit - $newCount,
        ];
    }
}
