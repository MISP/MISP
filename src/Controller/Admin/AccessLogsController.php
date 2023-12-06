<?php

namespace App\Controller\Admin;

use App\Controller\AppController;
use App\Model\Entity\AccessLog;
use Cake\Core\Configure;
use Cake\Http\Exception\NotFoundException;

class AccessLogsController extends AppController
{
    public $paginate = [
        'recursive' => -1,
        'limit' => 60,
        'fields' => ['id', 'created', 'user_id', 'org_id', 'authkey_id', 'ip', 'request_method', 'user_agent', 'request_id', 'controller', 'action', 'url', 'response_code', 'memory_usage', 'duration', 'query_count'],
        'contain' => [
            'Users' => ['fields' => ['id', 'email', 'org_id']],
            'Organisations' => ['fields' => ['id', 'name', 'uuid']],
        ],
        'order' => [
            'AccessLogs.id' => 'DESC'
        ],
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

        if ($this->ParamHandler->isRest()) {
            $list = $this->AccessLogs->find(
                'all',
                [
                    'conditions' => $conditions,
                    'contain' => $this->paginate['contain'],
                ]
            );
            foreach ($list as $item) {
                if (!empty($item['request'])) {
                    $item['request'] = base64_encode($item['request']);
                }
            }
            return $this->RestResponse->viewData($list->toArray(), 'json');
        }
        if (empty(Configure::read('MISP.log_skip_access_logs_in_application_logs'))) {
            $this->Flash->info(__('Access logs are logged in both application logs and access logs. Make sure you reconfigure your log monitoring tools and update MISP.log_skip_access_logs_in_application_logs.'));
        }

        $this->paginate['conditions'] = $conditions;
        $list = $this->paginate();

        $this->set('list', $list);
        $this->set('title_for_layout', __('Access logs'));
    }

    public function request($id)
    {
        $request = $this->AccessLogs->find(
            'all',
            [
                'conditions' => ['AccessLogs.id' => $id],
                'fields' => ['AccessLogs.request'],
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
                $conditions['AccessLogs.user_id'] = $params['user'];
            } else {
                $user = $this->Users->find(
                    'first',
                    [
                        'conditions' => ['Users.email' => $params['user']],
                        'fields' => ['id'],
                    ]
                );
                if (!empty($user)) {
                    $conditions['AccessLogs.user_id'] = $user['id'];
                } else {
                    $conditions['AccessLogs.user_id'] = -1;
                }
            }
        }
        if (isset($params['ip'])) {
            $conditions['AccessLogs.ip'] = inet_pton($params['ip']);
        }
        foreach (['authkey_id', 'request_id', 'controller', 'action'] as $field) {
            if (isset($params[$field])) {
                $conditions['AccessLogs.' . $field] = $params[$field];
            }
        }
        if (isset($params['url'])) {
            $conditions['AccessLogs.url LIKE'] = "%{$params['url']}%";
        }
        if (isset($params['user_agent'])) {
            $conditions['AccessLogs.user_agent LIKE'] = "%{$params['user_agent']}%";
        }
        if (isset($params['memory_usage'])) {
            $conditions['AccessLogs.memory_usage >='] = ($params['memory_usage'] * 1024);
        }
        if (isset($params['memory_usage'])) {
            $conditions['AccessLogs.memory_usage >='] = ($params['memory_usage'] * 1024);
        }
        if (isset($params['duration'])) {
            $conditions['AccessLogs.duration >='] = $params['duration'];
        }
        if (isset($params['query_count'])) {
            $conditions['AccessLogs.query_count >='] = $params['query_count'];
        }
        if (isset($params['request_method'])) {
            $methodId = array_flip(AccessLog::REQUEST_TYPES)[$params['request_method']] ?? -1;
            $conditions['AccessLogs.request_method'] = $methodId;
        }
        if (isset($params['org'])) {
            if (is_numeric($params['org'])) {
                $conditions['AccessLogs.org_id'] = $params['org'];
            } else {
                $org = $this->AccessLogs->Organisation->fetchOrg($params['org']);
                if ($org) {
                    $conditions['AccessLogs.org_id'] = $org['id'];
                } else {
                    $conditions['AccessLogs.org_id'] = -1;
                }
            }
        }
        if (isset($params['created'])) {
            $tempData = is_array($params['created']) ? $params['created'] : [$params['created']];
            foreach ($tempData as $k => $v) {
                $tempData[$k] = $this->AccessLogs->resolveTimeDelta($v);
            }
            if (count($tempData) === 1) {
                $conditions['AccessLogs.created >='] = date("Y-m-d H:i:s", $tempData[0]);
            } else {
                if ($tempData[0] < $tempData[1]) {
                    $temp = $tempData[1];
                    $tempData[1] = $tempData[0];
                    $tempData[0] = $temp;
                }
                $conditions['AND'][] = ['AccessLogs.created <=' => date("Y-m-d H:i:s", $tempData[0])];
                $conditions['AND'][] = ['AccessLogs.created >=' => date("Y-m-d H:i:s", $tempData[1])];
            }
        }
        return $conditions;
    }
}
