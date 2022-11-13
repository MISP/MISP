<?php
App::uses('AppController', 'Controller');

/**
 * @property AccessLog $AccessLog
 */
class AccessLogsController extends AppController
{
    public $components = [
        'RequestHandler',
    ];

    public $paginate = [
        'recursive' => -1,
        'limit' => 60,
        'fields' => ['id', 'created', 'user_id', 'org_id', 'authkey_id', 'ip', 'request_method', 'request_id', 'controller', 'action', 'url', 'response_code', 'memory_usage', 'duration'],
        'contain' => [
            'User' => ['fields' => ['id', 'email', 'org_id']],
            'Organisation' => ['fields' => ['id', 'name', 'uuid']],
        ],
        'order' => [
            'AccessLog.id' => 'DESC'
        ],
    ];

    public function admin_index()
    {
        $params = $this->IndexFilter->harvestParameters([
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
            'response_code',
        ]);

        $conditions =  $this->__searchConditions($params);

        if ($this->_isRest()) {
            $list = $this->AccessLog->find('all', [
                'conditions' => $conditions,
                'contain' => $this->paginate['contain'],
            ]);
            return $this->RestResponse->viewData($list, 'json');
        }

        $this->paginate['conditions'] = $conditions;
        $list = $this->paginate();

        $this->set('list', $list);
        $this->set('title_for_layout', __('Access logs'));
    }

    public function admin_request($id)
    {
        $request = $this->AccessLog->find('first', [
            'conditions' => ['AccessLog.id' => $id],
            'fields' => ['AccessLog.request'],
        ]);
        if (empty($request)) {
            throw new NotFoundException(__('Access log not found'));
        }

        if (empty($request['AccessLog']['request'])) {
            throw new NotFoundException(__('Request body is empty'));
        }

        $contentType = explode(';', $request['AccessLog']['request_content_type'], 2)[0];
        if ($contentType === 'application/x-www-form-urlencoded' || $contentType === 'multipart/form-data') {
            parse_str($request['AccessLog']['request'], $output);
            $highlighted = highlight_string("<?php\n" . var_export($output, true) . "?>", true);
            $highlighted = str_replace(["&lt;?php","?&gt;"] , '', $highlighted);
            $data = $highlighted;
        } else {
            $data = h($request['AccessLog']['request']);
        }

        $this->set('request', $data);
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
                $conditions['AccessLog.user_id'] = $params['user'];
            } else {
                $user = $this->User->find('first', [
                    'conditions' => ['User.email' => $params['user']],
                    'fields' => ['id'],
                ]);
                if (!empty($user)) {
                    $conditions['AccessLog.user_id'] = $user['User']['id'];
                } else {
                    $conditions['AccessLog.user_id'] = -1;
                }
            }
        }
        if (isset($params['ip'])) {
            $conditions['AccessLog.ip'] = inet_pton($params['ip']);
        }
        foreach (['authkey_id', 'request_id', 'controller', 'action'] as $field) {
            if (isset($params[$field])) {
                $conditions['AccessLog.' . $field] = $params[$field];
            }
        }
        if (isset($params['url'])) {
            $conditions['AccessLog.url LIKE'] = "%{$params['url']}%";
        }
        if (isset($params['request_method'])) {
            $methodId = array_flip(AccessLog::REQUEST_TYPES)[$params['request_method']] ?? -1;
            $conditions['AccessLog.request_method'] = $methodId;
        }
        if (isset($params['org'])) {
            if (is_numeric($params['org'])) {
                $conditions['AccessLog.org_id'] = $params['org'];
            } else {
                $org = $this->AccessLog->Organisation->fetchOrg($params['org']);
                if ($org) {
                    $conditions['AccessLog.org_id'] = $org['id'];
                } else {
                    $conditions['AccessLog.org_id'] = -1;
                }
            }
        }
        if (isset($params['created'])) {
            $tempData = is_array($params['created']) ? $params['created'] : [$params['created']];
            foreach ($tempData as $k => $v) {
                $tempData[$k] = $this->AccessLog->resolveTimeDelta($v);
            }
            if (count($tempData) === 1) {
                $conditions['AccessLog.created >='] = date("Y-m-d H:i:s", $tempData[0]);
            } else {
                if ($tempData[0] < $tempData[1]) {
                    $temp = $tempData[1];
                    $tempData[1] = $tempData[0];
                    $tempData[0] = $temp;
                }
                $conditions['AND'][] = ['AccessLog.created <=' => date("Y-m-d H:i:s", $tempData[0])];
                $conditions['AND'][] = ['AccessLog.created >=' => date("Y-m-d H:i:s", $tempData[1])];
            }
        }
        return $conditions;
    }
}