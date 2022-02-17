<?php
App::uses('SyncTool', 'Tools');

class ServerSyncTool
{
    const FEATURE_BR = 'br',
        FEATURE_GZIP = 'gzip',
        FEATURE_ORG_RULE = 'org_rule',
        FEATURE_FILTER_SIGHTINGS = 'filter_sightings',
        FEATURE_PROPOSALS = 'proposals',
        FEATURE_POST_TEST = 'post_test';

    /** @var array */
    private $server;

    /** @var array */
    private $request;

    /** @var HttpSocketExtended */
    private $socket;

    /** @var array|null */
    private $info;

    /**
     * @param array $server
     * @param array $request
     * @throws InvalidArgumentException
     * @throws Exception
     */
    public function __construct(array $server, array $request)
    {
        if (!isset($server['Server'])) {
            throw new InvalidArgumentException("Invalid server provided.");
        }

        $this->server = $server;
        $this->request = $request;

        $syncTool = new SyncTool();
        $this->socket = $syncTool->setupHttpSocket($server);
    }

    /**
     * Check if event exists on remote server.
     * @param array $event
     * @return bool
     * @throws Exception
     */
    public function eventExists(array $event)
    {
        $url = $this->server['Server']['url'] . '/events/view/' . $event['Event']['uuid'];
        $start = microtime(true);
        $exists = $this->socket->head($url, [], $this->request);
        $this->log($start, 'HEAD', $url, $exists);
        if ($exists->code == '404') {
            return false;
        }
        if ($exists->code == '200') {
            return true;
        }
        throw new HttpSocketHttpException($exists, $url);
    }

    /**
     * @param array $params
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function eventIndex($params = [])
    {
        return $this->post('/events/index', $params);
    }

    /**
     * @param int|string $eventId Event ID or UUID
     * @param array $params
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     */
    public function fetchEvent($eventId, array $params = [])
    {
        $url = "/events/view/$eventId";
        $url .= $this->createParams($params);
        return $this->get($url);
    }

    /**
     * @param array $rules
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function attributeSearch(array $rules)
    {
        return $this->post('/attributes/restSearch.json', $rules);
    }

    /**
     * @param array $params
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     */
    public function fetchProposals(array $params = [])
    {
        $url = '/shadow_attributes/index';
        $url .= $this->createParams($params);
        $url .= '.json';
        return $this->get($url);
    }

    /**
     * @param array $event
     * @param array $sightingUuids
     * @return array Sighting UUIDs that exists on remote side
     * @throws HttpSocketJsonException
     * @throws HttpSocketHttpException
     */
    public function filterSightingUuidsForPush(array $event, array $sightingUuids)
    {
        if (!$this->isSupported(self::FEATURE_FILTER_SIGHTINGS)) {
            return [];
        }

        $response = $this->post('/sightings/filterSightingUuidsForPush/' . $event['Event']['uuid'], $sightingUuids);
        return $response->json();
    }

    /**
     * @param array $sightings
     * @param string $eventUuid
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function uploadSightings(array $sightings, $eventUuid)
    {
        foreach ($sightings as &$sighting) {
            if (!isset($sighting['org_id'])) {
                $sighting['org_id'] = '0';
            }
        }

        $logMessage = "Pushing Sightings for Event #{$eventUuid} to Server #{$this->server['Server']['id']}";
        $this->post('/sightings/bulkSaveSightings/' . $eventUuid, $sightings, $logMessage);
    }

    /**
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     */
    public function getAvailableSyncFilteringRules()
    {
        return $this->get('/servers/getAvailableSyncFilteringRules');
    }

    /**
     * @return array
     * @throws HttpSocketJsonException
     * @throws HttpSocketHttpException
     * @throws Exception
     */
    public function info()
    {
        if ($this->info) {
            return $this->info;
        }

        $response = $this->get('/servers/getVersion');
        $info = $response->json();
        if (!isset($info['version'])) {
            throw new Exception("Invalid response when fetching server version: `version` field missing.");
        }
        $this->info = $info;
        return $info;
    }

    /**
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     */
    public function userInfo()
    {
        return $this->get('/users/view/me.json');
    }

    /**
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function resetAuthKey()
    {
        return $this->post('/users/resetauthkey/me', []);
    }

    /**
     * @param string $testString
     * @return HttpSocketResponseExtended
     * @throws Exception
     */
    public function postTest($testString)
    {
        return $this->post('/servers/postTest', ['testString' => $testString]);
    }

    /**
     * @return array
     */
    public function server()
    {
        return $this->server;
    }

    /**
     * @return int
     */
    public function serverId()
    {
        return $this->server['Server']['id'];
    }

    /**
     * @return array
     */
    public function pullRules()
    {
        return $this->decodeRule('pull_rules');
    }

    /**
     * @return array
     */
    public function pushRules()
    {
        return $this->decodeRule('push_rules');
    }

    /**
     * @param string $flag
     * @return bool
     * @throws HttpSocketJsonException
     * @throws HttpSocketHttpException
     * @throws InvalidArgumentException
     */
    public function isSupported($flag)
    {
        $info = $this->info();
        switch ($flag) {
            case self::FEATURE_BR:
                return isset($info['request_encoding']) && in_array('br', $info['request_encoding'], true);
            case self::FEATURE_GZIP:
                return isset($info['request_encoding']) && in_array('gzip', $info['request_encoding'], true);
            case self::FEATURE_FILTER_SIGHTINGS:
                return isset($info['filter_sightings']) && $info['filter_sightings'];
            case self::FEATURE_ORG_RULE:
                $version = explode('.', $info['version']);
                return $version[0] == 2 && $version[1] == 4 && $version[2] > 123;
            case self::FEATURE_PROPOSALS:
                $version = explode('.', $info['version']);
                return $version[0] == 2 && $version[1] == 4 && $version[2] >= 111;
            case self::FEATURE_POST_TEST:
                $version = explode('.', $info['version']);
                return $version[0] == 2 && $version[1] == 4 && $version[2] > 68;
            default:
                throw new InvalidArgumentException("Invalid flag `$flag` provided");
        }
    }

    /**
     * @return array|null
     */
    public function connectionMetaData()
    {
        return $this->socket->getMetaData();
    }

    /**
     * @params string $url Relative URL
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     */
    private function get($url)
    {
        $url = $this->server['Server']['url'] . $url;
        $start = microtime(true);
        $response = $this->socket->get($url, [], $this->request);
        $this->log($start, 'GET', $url, $response);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response, $url);
        }
        return $response;
    }

    /**
     * @param string $url Relative URL
     * @param mixed $data
     * @param string|null $logMessage
     * @return HttpSocketResponseExtended
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    private function post($url, $data, $logMessage = null)
    {
        $data = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($logMessage && !empty(Configure::read('Security.sync_audit'))) {
            $pushLogEntry = sprintf(
                "==============================================================\n\n[%s] %s:\n\n%s\n\n",
                date("Y-m-d H:i:s"),
                $logMessage,
                $data
            );
            file_put_contents(APP . 'files/scripts/tmp/debug_server_' . $this->server['Server']['id'] . '.log', $pushLogEntry, FILE_APPEND | LOCK_EX);
        }

        $request = $this->request;
        if (strlen($data) > 1024) { // do not compress small body
            if ($this->isSupported(self::FEATURE_BR) && function_exists('brotli_compress')) {
                $request['header']['Content-Encoding'] = 'br';
                $data = brotli_compress($data, 1, BROTLI_TEXT);
            } else if ($this->isSupported(self::FEATURE_GZIP) && function_exists('gzencode')) {
                $request['header']['Content-Encoding'] = 'gzip';
                $data = gzencode($data, 1);
            }
        }
        $url = $this->server['Server']['url'] . $url;
        $start = microtime(true);
        $response = $this->socket->post($url, $data, $request);
        $this->log($start, 'POST', $url, $response);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response, $url);
        }
        return $response;
    }

    /**
     * @param string $key
     * @return array
     */
    private function decodeRule($key)
    {
        $rules = $this->server['Server'][$key];
        return json_decode($rules, true);
    }

    /**
     * @param array $params
     * @return string
     */
    private function createParams(array $params)
    {
        $url = '';
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    $url .= "/{$key}[]:$v";
                }
            } else {
                $url .= "/$key:$value";
            }
        }
        return $url;
    }

    /**
     * @param float $start
     * @param string $method HTTP method
     * @param string $url
     * @param HttpSocketResponse $response
     */
    private function log($start, $method, $url, HttpSocketResponse $response)
    {
        $duration = round(microtime(true) - $start, 3);
        $responseSize = strlen($response->body);
        $ce = $response->getHeader('Content-Encoding');
        $logEntry = '[' . date("Y-m-d H:i:s") . "] \"$method $url\" {$response->code} $responseSize $duration $ce\n";
        file_put_contents(APP . 'tmp/logs/server-sync.log', $logEntry, FILE_APPEND | LOCK_EX);
    }
}
