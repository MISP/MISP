<?php
declare(strict_types=1);

namespace App\Model\Behavior;

use App\Lib\Tools\RedisTool;
use Cake\ORM\Behavior;
use Exception;

class EventLockBehavior extends Behavior
{
    // In seconds
    public const DEFAULT_TTL = 900,
        PREFIX = 'misp:event_lock:';

    /**
     * @param array $user user array
     * @param int $eventId event ID
     * @return bool True if insert was successful.
     */
    public function insertLock(array $user, int $eventId)
    {
        return $this->insertLockToRedis($eventId, "user:{$user['id']}", [
            'type' => 'user',
            'timestamp' => time(),
            'User' => [
                'id' => $user['id'],
                'org_id' => $user['org_id'],
                'email' => $user['email'],
            ],
        ]);
    }

    /**
     * @param int $eventId event ID
     * @param int $jobId job ID to insert
     * @return bool True if insert was successful.
     */
    public function insertLockBackgroundJob(int $eventId, int $jobId)
    {
        return $this->insertLockToRedis($eventId, "job:$jobId", [
            'type' => 'job',
            'timestamp' => time(),
            'job_id' => $jobId,
        ]);
    }

    /**
     * @param int $eventId event ID
     * @param array $user user array
     * @return int|null Lock ID
     */
    public function insertLockApi(int $eventId, array $user)
    {
        $apiLockId = mt_rand();
        if (
            $this->insertLockToRedis(
                $eventId,
                "api:{$user['id']}:$apiLockId",
                [
                'type' => 'api',
                'user_id' => $user['id'],
                'timestamp' => time(),
                ]
            )
        ) {
            return $apiLockId;
        }

        return null;
    }

    /**
     * @param int $eventId event ID
     * @param array $user user array
     * @return bool
     */
    public function deleteLock(int $eventId, array $user)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        $deleted = $redis->hdel(self::PREFIX . $eventId, "user:{$user['id']}");

        return $deleted > 0;
    }

    /**
     * @deprecated use deleteLockApi instead
     * @param int $eventId event ID
     * @param int $apiLockId api lock ID
     * @param array $user user array
     * @return bool
     */
    public function deleteApiLock(int $eventId, int $apiLockId, array $user)
    {
        return $this->deleteLockApi($eventId, $apiLockId, $user);
    }

    /**
     * @param int $eventId event ID
     * @param int $apiLockId api lock ID
     * @param array $user user array
     * @return bool
     */
    public function deleteLockApi(int $eventId, int $apiLockId, array $user)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        $deleted = $redis->hdel(self::PREFIX . $eventId, "api:{$user['id']}:$apiLockId");

        return $deleted > 0;
    }

    /**
     * @deprecated use deleteLockBackgroundJob instead
     * @param int $eventId event ID
     * @param int $jobId job ID
     * @return bool
     */
    public function deleteBackgroundJobLock(int $eventId, int $jobId)
    {
        return $this->deleteLockBackgroundJob($eventId, $jobId);
    }

    /**
     * @param int $eventId event ID
     * @param int $jobId job ID
     * @return bool
     */
    public function deleteLockBackgroundJob(int $eventId, int $jobId)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        $deleted = $redis->hDel(self::PREFIX . $eventId, "job:$jobId");

        return $deleted > 0;
    }

    /**
     * @param array $user user array
     * @param int $eventId  event ID
     * @return array[]
     * @throws \JsonException
     */
    public function checkLock(array $user, int $eventId)
    {
        try {
            $redis = RedisTool::init();
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
            $value = RedisTool::deserialize($value);
            if ($value['timestamp'] + self::DEFAULT_TTL > $now) {
                $output[] = $value;
            }
        }

        return $output;
    }

    /**
     * @param int $eventId event ID
     * @param string $lockId lock ID
     * @param array $data data to insert
     * @return bool
     * @throws \JsonException
     * @throws \RedisException
     */
    private function insertLockToRedis(int $eventId, $lockId, array $data)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        $pipeline = $redis->pipeline();
        $pipeline->hSet(self::PREFIX . $eventId, $lockId, RedisTool::serialize($data));
        $pipeline->expire(self::PREFIX . $eventId, self::DEFAULT_TTL); // prolong TTL

        return $pipeline->exec()[0] !== false;
    }
}
