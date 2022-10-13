<?php
App::uses('AppController', 'Controller');

class AccessLogsController extends AppController
{
    public function admin_index()
    {
        $params = $this->IndexFilter->harvestParameters([
            'ip',
            'user_id',
            'org_id',
            'request_id',
            'authkey_id',
            'api_request',
            'request_method',
            'page',
        ]);

        $lastData = $this->__filterData($params);
        return $this->RestResponse->viewData($lastData, 'json');
    }

    /**
     * @param array $filter
     * @param int $perPage
     * @return array
     * @throws JsonException
     * @throws RedisException
     */
    private function __filterData(array $filter = [], $perPage = 100)
    {
        $page = $filter['page'] ?? 1;
        $startId = ($page - 1) * $perPage;
        $lastData = [];
        $currentId = -1;
        foreach ($this->__fetchData() as $data) {
            $currentId++;
            if (isset($filter['user_id']) && $data['user_id'] != $filter['user_id']) {
                continue;
            }
            if (isset($filter['authkey_id']) && $data['authkey_id'] != $filter['authkey_id']) {
                continue;
            }
            if (isset($filter['org_id']) && $data['org_id'] != $filter['org_id']) {
                continue;
            }
            if (isset($filter['ip']) && inet_ntop($data['ip']) != $filter['ip']) {
                continue;
            }
            if (isset($filter['request_id']) && $data['request_id'] != $filter['request_id']) {
                continue;
            }
            if (isset($filter['api_request']) && $data['api_request'] != $filter['api_request']) {
                continue;
            }
            if (isset($filter['request_method']) && $data['request_method'] != $filter['request_method']) {
                continue;
            }
            if (isset($filter['controller']) && $data['controller'] != $filter['controller']) {
                continue;
            }
            if (isset($filter['action']) && $data['action'] != $filter['action']) {
                continue;
            }
            if ($currentId >= $startId) {
                $data['id'] = $currentId;
                $lastData[] = $data;
                if (count($lastData) === $perPage) {
                    break;
                }
            }
        }

        $userIds = array_unique(array_column($lastData, 'user_id'), SORT_REGULAR);
        $users = $this->User->find('all', [
            'recursive' => -1,
            'conditions' => ['User.id' => $userIds],
            'fields' => ['id', 'email', 'org_id'],
        ]);
        $users = array_column(array_column($users, 'User'), null, 'id');

        $orgIds = array_unique(array_column($lastData, 'org_id'), SORT_REGULAR);
        $orgs = $this->User->Organisation->find('all', [
            'recursive' => -1,
            'conditions' => ['Organisation.id' => $orgIds],
            'fields' => ['id', 'name', 'uuid'],
        ]);
        $orgs = array_column(array_column($orgs, 'Organisation'), null, 'id');

        foreach ($lastData as &$data) {
            if (isset($data['request_encoding'])) {
                if ($data['request_encoding'] === 'br') {
                    $data['request'] = brotli_uncompress($data['request']);
                } else if ($data['request_encoding'] === 'gzip') {
                    $data['request'] = gzdecode($data['request']);
                } else {
                    // Unsupported request encoding
                    $data['request'] = base64_encode($data['request']);
                }
            }

            $data['ip'] = inet_ntop($data['ip']);
            $data['time_iso'] = $this->microTimestampToIso($data['time']);
            $data['User'] = $users[$data['user_id']] ?? null;
            $data['Organisation'] = $orgs[$data['org_id']] ?? null;
        }

        return $lastData;
    }

    /**
     * @param int $batchCount
     * @return Generator<array>
     * @throws JsonException
     * @throws RedisException
     */
    private function __fetchData($batchCount = 100)
    {
        $start = 0;
        $redis = RedisTool::init();
        while (true) {
            $lastData = $redis->lRange('misp:request_logs', $start, $start + $batchCount);
            if (empty($lastData)) {
                return null;
            }
            foreach ($lastData as $data) {
                yield RedisTool::deserialize(RedisTool::decompress($data));
            }
            $start += $batchCount;
        }
    }

    /**
     * @param float $microtime
     * @return string
     */
    private function microTimestampToIso($microtime)
    {
        return sprintf("%s.%06d", date("Y-m-d\TH:i:s", $microtime), ($microtime - floor($microtime))*1e6);
    }
}