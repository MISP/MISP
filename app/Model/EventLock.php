<?php
App::uses('AppModel', 'Model');

// Table `event_locks` is not used anymore
class EventLock extends AppModel
{
    // In seconds
    const DEFAULT_TTL = 900;

    /**
     * @param array $user
     * @param int $eventId
     * @return bool True if insert was successful.
     */
    public function insertLock(array $user, $eventId)
    {
        return $this->insertLockToRedis("misp:event_lock:$eventId:user:{$user['id']}", [
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
        return $this->insertLockToRedis("misp:event_lock:$eventId:job:$jobId", [
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
        $rand = mt_rand();
        if ($this->insertLockToRedis("misp:event_lock:$eventId:api:{$user['id']}:$rand", [
            'type' => 'api',
            'user_id' => $user['id'],
            'timestamp' => time(),
        ])) {
            return $rand;
        }
        return null;
    }

    /**
     * @param int $eventId
     * @param int $jobId
     * @return null
     */
    public function deleteBackgroundJobLock($eventId, $jobId)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }

        $deleted = $redis->del("misp:event_lock:$eventId:job:$jobId");
        return $deleted > 0;
    }

    /**
     * @param string $key
     * @param array $data
     * @return bool
     */
    private function insertLockToRedis($key, array $data)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }

        return $redis->setex($key, self::DEFAULT_TTL, json_encode($data));
    }

    /**
     * @param int $eventId
     * @param int $lockId
     * @return bool
     */
    public function deleteApiLock($eventId, $lockId, array $user)
    {
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }

        $deleted = $redis->del("misp:event_lock:$eventId:api:{$user['id']}:$lockId");
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

        $keys = $redis->keys("misp:event_lock:$eventId:*");
        if (empty($keys)) {
            return [];
        }

        return array_map(function ($value) {
            return $this->jsonDecode($value);
        }, $redis->mget($keys));
    }
}
