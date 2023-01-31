<?php

namespace CommonConnectorTools;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Log\Log;
use Cake\Log\Engine\FileLog;

class CommonConnectorTools
{
    public $description = '';
    public $name = '';
    public $connectorName = '';
    public $exposedFunctions = [
        'diagnostics'
    ];
    public $version = '???';

    const STATE_INITIAL = 'Request issued';
    const STATE_ACCEPT = 'Request accepted';
    const STATE_CONNECTED = 'Connected';
    const STATE_SENDING_ERROR = 'Error while sending request';
    const STATE_CANCELLED = 'Request cancelled';
    const STATE_DECLINED = 'Request declined by remote';

    public function __construct()
    {
        if (empty(Log::getConfig("LocalToolDebug{$this->connectorName}"))) {
            Log::setConfig("LocalToolDebug{$this->connectorName}", [
                'className' => FileLog::class,
                'path' => LOGS,
                'file' => "{$this->connectorName}-debug",
                'scopes' => [$this->connectorName],
                'levels' => ['notice', 'info', 'debug'],
            ]);
        }
        if (empty(Log::getConfig("LocalToolError{$this->connectorName}"))) {
            Log::setConfig("LocalToolError{$this->connectorName}", [
                'className' => FileLog::class,
                'path' => LOGS,
                'file' => "{$this->connectorName}-error",
                'scopes' => [$this->connectorName],
                'levels' => ['warning', 'error', 'critical', 'alert', 'emergency'],
            ]);
        }
    }

    protected function logDebug($message)
    {
        Log::debug($message, [$this->connectorName]);
    }

    protected function logError($message, $scope=[])
    {
        Log::error($message, [$this->connectorName]);
    }

    public function addExposedFunction(string $functionName): void
    {
        $this->exposedFunctions[] = $functionName;
    }

    public function getBatchActionFunctions(): array
    {
        return array_filter($this->exposedFunctions, function($function) {
            return $function['type'] == 'batchAction';
        });
    }

    public function runAction($action, $params) {
        if (!in_array($action, $exposedFunctions)) {
            throw new MethodNotAllowedException(__('Invalid connector function called.'));
        }
        return $this->{$action}($params);
    }

    public function health(Object $connection): array
    {
        return 0;
    }

    public function captureOrganisation($input): bool
    {
        if (empty($input['uuid'])) {
            return false;
        }
        $organisations = \Cake\ORM\TableRegistry::getTableLocator()->get('Organisations');
        $organisations->captureOrg($input);
        return true;
    }

    public function captureSharingGroup($input): bool
    {
        if (empty($input['uuid'])) {
            return false;
        }
        $sharing_groups = \Cake\ORM\TableRegistry::getTableLocator()->get('SharingGroups');
        $sharing_groups->captureSharingGroup($input);
        return true;
    }

    public function remoteToolConnectionStatus(array $params, string $status): void
    {
        $remoteToolConnections = \Cake\ORM\TableRegistry::getTableLocator()->get('RemoteToolConnections');
        $remoteToolConnection = $remoteToolConnections->find()->where(
            [
                'local_tool_id' => $params['connection']['id'],
                'remote_tool_id' => $params['remote_tool']['id'],
                'brood_id' => $params['remote_cerebrate']['id']
            ]
        )->first();
        if (empty($remoteToolConnection)) {
            $data = $remoteToolConnections->newEmptyEntity();
            $entry = [
                'local_tool_id' => $params['connection']['id'],
                'remote_tool_id' => $params['remote_tool']['id'],
                'remote_tool_name' => $params['remote_tool']['name'],
                'brood_id' => $params['remote_cerebrate']['id'],
                'name' => '',
                'settings' => '',
                'status' => $status,
                'created' => time(),
                'modified' => time()
            ];
            $data = $remoteToolConnections->patchEntity($data, $entry);
            $remoteToolConnections->save($data);
        } else {
            $data = $remoteToolConnections->patchEntity($remoteToolConnection, ['status' => $status, 'modified' => time()]);
            $remoteToolConnections->save($data);
        }
    }

    public function initiateConnectionWrapper(array $params): array
    {
        $result = $this->initiateConnection($params);
        $this->remoteToolConnectionStatus($params, self::STATE_INITIAL);
        return $result;
    }

    public function acceptConnectionWrapper(array $params): array
    {
        $result = $this->acceptConnection($params);
        $this->remoteToolConnectionStatus($params, self::STATE_ACCEPT);
        return $result;
    }

    public function finaliseConnectionWrapper(array $params): bool
    {
        $result = $this->finaliseConnection($params);
        $this->remoteToolConnectionStatus($params, self::STATE_CONNECTED);
        return false;
    }
}

?>
