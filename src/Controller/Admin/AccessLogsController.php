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
        'fields' => ['id', 'created', 'user_id', 'org_id', 'authkey_id', 'ip', 'request_method', 'user_agent', 'request_id', 'controller', 'action', 'url', 'response_code', 'memory_usage', 'duration', 'query_count', 'request'],
        'contain' => [
            'Users' => ['fields' => ['id', 'email', 'org_id']],
            'Organisations' => ['fields' => ['id', 'name', 'uuid']],
        ],
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

        // $conditions =  $this->__searchConditions($params);

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
            ]
        );


        if (empty(Configure::read('MISP.log_skip_access_logs_in_application_logs'))) {
            $this->Flash->info(__('Access logs are logged in both application logs and access logs. Make sure you reconfigure your log monitoring tools and update MISP.log_skip_access_logs_in_application_logs.'));
        }
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

    public function filtering()
    {
        $this->CRUD->filtering();
    }
}
