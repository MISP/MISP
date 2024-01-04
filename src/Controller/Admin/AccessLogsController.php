<?php

namespace App\Controller\Admin;

use App\Controller\AppController;
use App\Model\Entity\AccessLog;
use Cake\Core\Configure;
use Cake\Http\Exception\NotFoundException;

class AccessLogsController extends AppController
{
    protected $fields = ['id', 'created', 'user_id', 'org_id', 'authkey_id', 'ip', 'request_method', 'user_agent', 'request_id', 'controller', 'action', 'url', 'response_code', 'memory_usage', 'duration', 'query_count', 'request'];
    protected $contain = [
        'Users' => ['fields' => ['id', 'email', 'org_id']],
        'Organisations' => ['fields' => ['id', 'name', 'uuid']],
    ];
    public $paginate = [
        'limit' => 60,
        'order' => [
            'AccessLogs.id' => 'DESC'
        ],
    ];

    public $quickFilterFields = [
        'ip',
        ['user_agent' => true],
        ['action' => true],
        ['url' => true],
        ['controller' => true]
    ];

    public $filterFields = [
        'created',
        'ip',
        'user',
        'org_id',
        'request_id',
        'authkey_id',
        'api_request',
        'request_method',
        'controller',
        'action',
        'url',
        'user_agent',
        'memory_usage',
        'duration',
        'query_count',
        'response_code',
    ];

    public function initialize(): void
    {
        parent::initialize();
        $this->loadComponent('Flash');
    }

    public function index()
    {
        $params = $this->harvestParameters(
            [
                'created',
                'ip',
                'user',
                'org',
                'request_id',
                'authkey_id',
                'api_request',
                'request_method',
                'controller',
                'action',
                'url',
                'user_agent',
                'memory_usage',
                'duration',
                'query_count',
                'response_code',
            ]
        );

        $conditions =  $this->__searchConditions($params);

        $afterFindHandler = function ($entry) {
            if (!empty($entry['request'])) {
                $entry['request'] = base64_encode($entry['request']);
            }
            return $entry;
        };

        $this->CRUD->index(
            [
                'filters' => $this->filterFields,
                'quickFilters' => $this->quickFilterFields,
                'afterFind' => $afterFindHandler,
                'conditions' => $conditions,
                'contain' => $this->contain,
                'fields' => $this->fields,
            ]
        );

        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }

        if (empty(Configure::read('MISP.log_skip_access_logs_in_application_logs'))) {
            $this->Flash->info(__('Access logs are logged in both application logs and access logs. Make sure you reconfigure your log monitoring tools and update MISP.log_skip_access_logs_in_application_logs.'));
        }
    }

    public function request($id)
    {
        $request = $this->AccessLogs->find(
            'all',
            [
                'conditions' => ['id' => $id],
                'fields' => ['request'],
            ]
        )->first();
        if (empty($request)) {
            throw new NotFoundException(__('Access log not found'));
        }

        if (empty($request['request'])) {
            throw new NotFoundException(__('Request body is empty'));
        }

        $contentType = explode(';', $request['request_content_type'], 2)[0];
        if ($contentType === 'application/x-www-form-urlencoded' || $contentType === 'multipart/form-data') {
            parse_str($request['request'], $output);
            // highlight PHP array
            $highlighted = highlight_string("<?php " . var_export($output, true), true);
            $highlighted = trim($highlighted);
            $highlighted = preg_replace("|^\\<code\\>\\<span style\\=\"color\\: #[a-fA-F0-9]{0,6}\"\\>|", "", $highlighted, 1);  // remove prefix
            $highlighted = preg_replace("|\\</code\\>\$|", "", $highlighted, 1);  // remove suffix 1
            $highlighted = trim($highlighted);  // remove line breaks
            $highlighted = preg_replace("|\\</span\\>\$|", "", $highlighted, 1);  // remove suffix 2
            $highlighted = trim($highlighted);  // remove line breaks
            $highlighted = preg_replace("|^(\\<span style\\=\"color\\: #[a-fA-F0-9]{0,6}\"\\>)(&lt;\\?php&nbsp;)(.*?)(\\</span\\>)|", "\$1\$3\$4", $highlighted);  // remove custom added "<?php "
            $data = $highlighted;
        } else {
            $data = h($request['request']);
        }

        $this->set('request', $data);
    }

    public function queryLog($id)
    {
        $request = $this->AccessLog->find(
            'first',
            [
                'conditions' => ['AccessLogs.id' => $id],
                'fields' => ['AccessLogs.query_log'],
            ]
        );
        if (empty($request)) {
            throw new NotFoundException(__('Access log not found'));
        }

        if (empty($request['query_log'])) {
            throw new NotFoundException(__('Query log is empty'));
        }

        $this->set('queryLog', $request['query_log']);
    }

    public function filtering()
    {
        $this->CRUD->filtering();
    }

    /**
     * @param array $params
     * @return array
     */
    private function __searchConditions(array $params)
    {
        $qbRules = [];
        foreach ($params as $key => $value) {
            if ($key === 'created') {
                $qbRules[] = [
                    'id' => $key,
                    'operator' => is_array($value) ? 'between' : 'greater_or_equal',
                    'value' => $value,
                ];
            } else {
                if (is_array($value)) {
                    $value = implode('||', $value);
                }
                $qbRules[] = [
                    'id' => $key,
                    'value' => $value,
                ];
            }
        }
        $this->set('qbRules', $qbRules);

        $conditions = [];
        if (isset($params['user'])) {
            if (is_numeric($params['user'])) {
                $conditions['user_id'] = $params['user'];
            } else {
                $user = $this->User->find(
                    'first',
                    [
                        'conditions' => ['User.email' => $params['user']],
                        'fields' => ['id'],
                    ]
                );
                if (!empty($user)) {
                    $conditions['user_id'] = $user['User']['id'];
                } else {
                    $conditions['user_id'] = -1;
                }
            }
        }
        if (isset($params['ip'])) {
            $conditions['ip'] = inet_pton($params['ip']);
        }
        foreach (['authkey_id', 'request_id', 'controller', 'action'] as $field) {
            if (isset($params[$field])) {
                $conditions['' . $field] = $params[$field];
            }
        }
        if (isset($params['url'])) {
            $conditions['url LIKE'] = "%{$params['url']}%";
        }
        if (isset($params['user_agent'])) {
            $conditions['user_agent LIKE'] = "%{$params['user_agent']}%";
        }
        if (isset($params['memory_usage'])) {
            $conditions['memory_usage >='] = ($params['memory_usage'] * 1024);
        }
        if (isset($params['memory_usage'])) {
            $conditions['memory_usage >='] = ($params['memory_usage'] * 1024);
        }
        if (isset($params['duration'])) {
            $conditions['duration >='] = $params['duration'];
        }
        if (isset($params['query_count'])) {
            $conditions['query_count >='] = $params['query_count'];
        }
        if (isset($params['request_method'])) {
            $methodId = array_flip(AccessLog::REQUEST_TYPES)[$params['request_method']] ?? -1;
            $conditions['request_method'] = $methodId;
        }
        if (isset($params['org'])) {
            if (is_numeric($params['org'])) {
                $conditions['org_id'] = $params['org'];
            } else {
                $org = $this->AccessLog->Organisation->fetchOrg($params['org']);
                if ($org) {
                    $conditions['org_id'] = $org['id'];
                } else {
                    $conditions['org_id'] = -1;
                }
            }
        }
        if (isset($params['created'])) {
            $tempData = is_array($params['created']) ? $params['created'] : [$params['created']];
            foreach ($tempData as $k => $v) {
                $tempData[$k] = $this->AccessLog->resolveTimeDelta($v);
            }
            if (count($tempData) === 1) {
                $conditions['created >='] = date("Y-m-d H:i:s", $tempData[0]);
            } else {
                if ($tempData[0] < $tempData[1]) {
                    $temp = $tempData[1];
                    $tempData[1] = $tempData[0];
                    $tempData[0] = $temp;
                }
                $conditions['AND'][] = ['created <=' => date("Y-m-d H:i:s", $tempData[0])];
                $conditions['AND'][] = ['created >=' => date("Y-m-d H:i:s", $tempData[1])];
            }
        }
        return $conditions;
    }
}
