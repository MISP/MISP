<?php
App::uses('AppModel', 'Model');

// Table `event_locks` is not used anymore
class EventLock extends AppModel
{
    // In seconds
    const DEFAULT_TTL = 900,
        PREFIX = 'misp:event_lock';

    /**
     * @param array $user
     * @param int $eventId
     * @return bool True if insert was successful.
     */
    public function insertLock(array $user, $eventId)
    {
        return $this->insertLockToRedis($eventId, "user:{$user['id']}", [
            'type' => 'user',
            'timestamp' => time(),
            'User' => [
                'id' => $user['id'],
                'org_id' => $user['org_id'],
                'email' => $user['email'],
            ]
        ]);
    }

    /**
     * @param int $eventId
     * @param int $jobId
     * @return bool True if insert was successful.
     */
    public function insertLockBackgroundJob($eventId, $jobId)
    {
        return $this->insertLockToRedis($eventId, "job:$jobId", [
            'type' => 'job',
            'timestamp' => time(),
            'job_id' => $jobId,
        ]);
    }

    /**
     * @param int $eventId
     * @return int|null Lock ID
     */
    public function insertLockApi($eventId, array $user)
    {
        $apiLockId = mt_rand();
        if ($this->insertLockToRedis($eventId, "api:{$user['id']}:$apiLockId", [
            'type' => 'api',
            'user_id' => $user['id'],
            'timestamp' => time(),
        ])) {
            return $apiLockId;
        }
        return null;
    }

    /**
     * @param int $eventId
     * @param int $apiLockId
     * @return bool
     */
    public function deleteApiLock($eventId, $apiLockId, array $user)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }

        $deleted = $redis->hdel(self::PREFIX . $eventId, "api:{$user['id']}:$apiLockId");
        return $deleted > 0;
    }

    /**
     * @param int $eventId
     * @param int $jobId
     * @return bool
     */
    public function deleteBackgroundJobLock($eventId, $jobId)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }

        $deleted = $redis->hDel(self::PREFIX . $eventId, "job:$jobId");
        return $deleted > 0;
    }

    /**
     * @param array $user
     * @param int $eventId
     * @return array[]
     * @throws JsonException
     */
    public function checkLock(array $user, $eventId)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return [];
        }

        $keys = $redis->hGetAll(self::PREFIX . $eventId);
        if (empty($keys)) {
            return [];
        }

        $output = [];
        $now = time();
        foreach ($keys as $value) {
            $value = $this->jsonDecode($value);
            if ($value['timestamp'] + self::DEFAULT_TTL > $now) {
                $output[] = $value;
            }
        }
        return $output;
    }

    /**
     * @param int $eventId
     * @param string $lockId
     * @param array $data
     * @return bool
     */
    private function insertLockToRedis($eventId, $lockId, array $data)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }

        $pipeline = $redis->pipeline();
        $pipeline->hSet(self::PREFIX . $eventId, $lockId, json_encode($data));
        $pipeline->expire(self::PREFIX . $eventId, self::DEFAULT_TTL); // prolong TTL
        return $pipeline->exec()[0] !== false;
    }
}
