<?php
App::uses('SyncTool', 'Tools');

class ServerSyncTool
{
    const FEATURE_BR = 'br',
        FEATURE_GZIP = 'gzip',
        FEATURE_FILTER_SIGHTINGS = 'filter_sightings';

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
     * @throws Exception
     */
    public function __construct(array $server, array $request)
    {
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
        $exists = $this->socket->head($this->server['Server']['url'] . '/events/view/' . $event['Event']['uuid'], [], $this->request);
        if ($exists->code == '404') {
            return false;
        }
        if ($exists->code == '200') {
            return true;
        }
        throw new HttpSocketHttpException($exists);
    }

    /**
     * @param array $event
     * @param array $sightingUuids
     * @return array Sighting UUIDs that exists on remote side
     * @throws HttpSocketJsonException|HttpSocketHttpException
     */
    public function filterSightingUuidsForPush(array $event, array $sightingUuids)
    {
        if (!$this->isSupported(self::FEATURE_FILTER_SIGHTINGS)) {
            return [];
        }

        $response = $this->post('/sightings/filterSightingUuidsForPush/' . $event['Event']['uuid'], $sightingUuids);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response);
        }

        return $response->json();
    }

    /**
     * @param array $sightings
     * @param string $eventUuid
     * @throws HttpSocketHttpException
     */
    public function uploadSightings(array $sightings, $eventUuid)
    {
        foreach ($sightings as &$sighting) {
            if (!isset($sighting['org_id'])) {
                $sighting['org_id'] = '0';
            }
        }

        $logMessage = "Pushing Sightings for Event #{$eventUuid} to Server #{$this->server['Server']['id']}";
        $response = $this->post('/sightings/bulkSaveSightings/' . $eventUuid, $sightings, $logMessage);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response);
        }
    }

    /**
     * @return array
     * @throws HttpSocketJsonException
     * @throws Exception
     */
    public function info()
    {
        if ($this->info) {
            return $this->info;
        }

        $response = $this->socket->get($this->server['Server']['url'] . '/servers/getVersion', [], $this->request);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response);
        }

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
        $response = $this->socket->get($this->server['Server']['url'] . '/users/view/me.json', [], $this->request);
        if (!$response->isOk()) {
            throw new HttpSocketHttpException($response);
        }
        return $response;
    }

    /**
     * @param string $url
     * @param mixed $data
     * @param string|null $logMessage
     * @return HttpSocketResponseExtended
     * @throws Exception
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
            file_put_contents(APP . 'files/scripts/tmp/debug_server_' . $this->server['Server']['id'] . '.log', $pushLogEntry, FILE_APPEND);
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
        return $this->socket->post($this->server['Server']['url'] . $url, $data, $request);
    }

    /**
     * @param string $flag
     * @return bool
     * @throws HttpSocketJsonException
     */
    private function isSupported($flag)
    {
        $info = $this->info();
        switch ($flag) {
            case self::FEATURE_BR:
                return isset($info['request_encoding']) && in_array('br', $info['request_encoding'], true);
            case self::FEATURE_GZIP:
                return isset($info['request_encoding']) && in_array('gzip', $info['request_encoding'], true);
            case self::FEATURE_FILTER_SIGHTINGS:
                return isset($info['filter_sightings']) && $info['filter_sightings'];
            default:
                throw new InvalidArgumentException("Invalid flag `$flag` provided");
        }
    }
}
