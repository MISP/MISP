<?php
App::uses('AppController', 'Controller');

class ApiController extends AppController
{
    public $components = [
        'RequestHandler'
    ];

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions[] = 'getApiInfo';
    }

    public function openapi()
    {
        $user = $this->_closeSession();
        if (!$user['Role']['perm_auth']) {
            $this->Flash->warning(__('Your role do not allow API access.'));
        } else if ($this->User->advancedAuthkeysEnabled() && !$this->User->AuthKey->userHasAuthKey($user['id'])) {
            $this->Flash->warning(__('You don\'t have auth key to use this API. You can generate one at your profile.'));
        }
        $this->set('title_for_layout', __('OpenAPI'));
    }

    public function viewDeprecatedFunctionUse()
    {
        $data = $this->Deprecation->getDeprecatedAccessList();
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->layout = false;
            $this->set('data', $data);
        }
    }

    public function getAllApis()
    {
        $user = $this->_closeSession();
        $allValidApis = $this->RestResponse->getAllApis($user);
        $allValidApisFieldsConstraint = $this->RestResponse->getAllApisFieldsConstraint($user);
        $output = [
            'allValidApis' => $allValidApis,
            'fieldsConstraint' => $allValidApisFieldsConstraint,
        ];
        return $this->RestResponse->viewData($output, 'json');
    }

    public function getApiInfo()
    {
        $relative_path = $this->request->data['url'];
        $result = $this->RestResponse->getApiInfo($relative_path);
        if ($this->_isRest()) {
            if (!empty($result)) {
                $result['api_info'] = $result;
            }
            return $this->RestResponse->viewData($result, $this->response->type());
        }
        if (empty($result)) {
            return $this->RestResponse->viewData('&nbsp;', $this->response->type());
        }
        $this->layout = false;
        $this->autoRender = false;
        $this->set('api_info', $result);
        $this->render('ajax/get_api_info');
    }

    public function rest()
    {
        if ($this->request->is('post')) {
            $request = $this->request->data;
            if (!empty($request['Server'])) {
                $request = $this->request->data['Server'];
            }
            $curl = '';
            $python = '';
            try {
                $result = $this->__doRestQuery($request, $curl, $python);
                $this->set('curl', $curl);
                $this->set('python', $python);
                if (!$result) {
                    $this->Flash->error(__('Something went wrong. Make sure you set the http method, body (when sending POST requests) and URL correctly.'));
                } else {
                    $this->set('data', $result);
                }
            } catch (Exception $e) {
                $this->Flash->error(__('Something went wrong. %s', $e->getMessage()));
            }
        }
        $header = sprintf(
            "Authorization: %s \nAccept: application/json\nContent-type: application/json",
            __('YOUR_API_KEY')
        );
        $this->set('header', $header);

        if ($this->User->advancedAuthkeysEnabled() && !$this->User->AuthKey->userHasAuthKey($this->Auth->user('id'))) {
            $this->Flash->warning(__('You don\'t have auth key to use this REST client. You can generate one at your profile.'));
        }

        $allAccessibleApis = $this->RestResponse->getAccessibleApis($this->Auth->user());
        $this->set('allAccessibleApis', $allAccessibleApis);
        $this->set('title_for_layout', __('REST client'));
    }

    /**
     * @param array $request
     * @param string $curl
     * @param string $python
     * @return array|false
     */
    private function __doRestQuery(array $request, &$curl = false, &$python = false)
    {
        $logHeaders = $request['header'];
        if (!empty(Configure::read('Security.advanced_authkeys'))) {
            $logHeaders = explode("\n", $request['header']);
            foreach ($logHeaders as $k => $header) {
                if (strpos($header, 'Authorization') !== false) {
                    $logHeaders[$k] = 'Authorization: ' . __('YOUR_API_KEY');
                }
            }
            $logHeaders = implode("\n", $logHeaders);
        }

        if (empty($request['body'])) {
            $historyBody = '';
        } else if (strlen($request['body']) > 65535) {
            $historyBody = ''; // body is too long to save into history table
        } else {
            $historyBody = $request['body'];
        }

        $rest_history_item = array(
            'headers' => $logHeaders,
            'body' => $historyBody,
            'url' => $request['url'],
            'http_method' => $request['method'],
            'use_full_path' => empty($request['use_full_path']) ? false : $request['use_full_path'],
            'show_result' => $request['show_result'],
            'skip_ssl' => $request['skip_ssl_validation'],
            'bookmark' => $request['bookmark'],
            'bookmark_name' => $request['name'],
            'timestamp' => time(),
        );
        if (!empty($request['url'])) {
            if (empty($request['use_full_path']) || empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
                $path = preg_replace('#^(://|[^/?])+#', '', $request['url']);
                $url = empty(Configure::read('Security.rest_client_baseurl')) ? (Configure::read('MISP.baseurl') . $path) : (Configure::read('Security.rest_client_baseurl') . $path);
                unset($request['url']);
            } else {
                $url = $request['url'];
            }
        } else {
            throw new InvalidArgumentException('URL not set.');
        }

        $params = ['timeout' => 300];
        if (!empty($request['skip_ssl_validation'])) {
            $params['ssl_verify_peer'] = false;
            $params['ssl_verify_host'] = false;
            $params['ssl_verify_peer_name'] = false;
            $params['ssl_allow_self_signed'] = true;
        }
        App::uses('HttpSocketExtended', 'Tools');
        $HttpSocket = new HttpSocketExtended($params);

        $temp_headers = empty($request['header']) ? [] : explode("\n", $request['header']);
        $request['header'] = array(
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'User-Agent' => 'MISP REST Client',
        );
        foreach ($temp_headers as $header) {
            $header = explode(':', $header);
            $header[0] = trim($header[0]);
            $header[1] = trim($header[1]);
            $request['header'][$header[0]] = $header[1];
        }
        $start = microtime(true);
        if (
            !empty($request['method']) &&
            $request['method'] === 'GET'
        ) {
            if ($curl !== false) {
                $curl = $this->__generateCurlQuery('get', $request, $url);
            }
            if ($python !== false) {
                $python = $this->__generatePythonScript($request, $url);
            }
            $response = $HttpSocket->get($url, false, array('header' => $request['header']));
        } elseif (
            !empty($request['method']) &&
            $request['method'] === 'POST' &&
            !empty($request['body'])
        ) {
            if ($curl !== false) {
                $curl = $this->__generateCurlQuery('post', $request, $url);
            }
            if ($python !== false) {
                $python = $this->__generatePythonScript($request, $url);
            }
            $response = $HttpSocket->post($url, $request['body'], array('header' => $request['header']));
        } elseif (
            !empty($request['method']) &&
            $request['method'] === 'DELETE'
        ) {
            if ($curl !== false) {
                $curl = $this->__generateCurlQuery('delete', $request, $url);
            }
            if ($python !== false) {
                $python = $this->__generatePythonScript($request, $url);
            }
            $response = $HttpSocket->delete($url, false, array('header' => $request['header']));
        } else {
            return false;
        }
        $viewData = [
            'duration' => round((microtime(true) - $start) * 1000, 2) . ' ms',
            'url' => $url,
            'code' => $response->code,
            'headers' => $response->headers,
        ];

        if (!empty($request['show_result'])) {
            $viewData['data'] = $response->body;
        } else {
            if ($response->isOk()) {
                $viewData['data'] = 'Success.';
            } else {
                $viewData['data'] = 'Something went wrong.';
            }
        }
        $rest_history_item['outcome'] = $response->code;

        $this->loadModel('RestClientHistory');
        $this->RestClientHistory->insert($this->Auth->user(), $rest_history_item);

        return $viewData;
    }

    private function __generatePythonScript(array $request, $url)
    {
        $slashCounter = 0;
        $baseurl = '';
        $relative = '';
        $verifyCert = ($url[4] === 's') ? 'True' : 'False';
        for ($i = 0; $i < strlen($url); $i++) {
            //foreach ($url as $url[$i]) {
            if ($url[$i] === '/') {
                $slashCounter += 1;
                if ($slashCounter == 3) {
                    continue;
                }
            }
            if ($slashCounter < 3) {
                $baseurl .= $url[$i];
            } else {
                $relative .= $url[$i];
            }
        }
        $python_script =
            sprintf(
                'misp_url = \'%s\'
misp_key = \'%s\'
misp_verifycert = %s
relative_path = \'%s\'
body = %s

from pymisp import ExpandedPyMISP

misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
misp.direct_call(relative_path, body)
',
                $baseurl,
                isset($request['header']['X-MISP-AUTH']) ? $request['header']['X-MISP-AUTH'] : $request['header']['Authorization'],
                $verifyCert,
                $relative,
                (empty($request['body']) ? 'None' : $request['body'])
            );
        return $python_script;
    }

    private function __generateCurlQuery($type, array $request, $url)
    {
        if ($type === 'get') {
            $curl = sprintf(
                'curl \%s -H "Authorization: %s" \%s -H "Accept: %s" \%s -H "Content-type: %s" \%s %s',
                PHP_EOL,
                $request['header']['Authorization'],
                PHP_EOL,
                $request['header']['Accept'],
                PHP_EOL,
                $request['header']['Content-Type'],
                PHP_EOL,
                $url
            );
        } else {
            $curl = sprintf(
                'curl \%s -d \'%s\' \%s -H "Authorization: %s" \%s -H "Accept: %s" \%s -H "Content-type: %s" \%s -X POST %s',
                PHP_EOL,
                json_encode(json_decode($request['body'])),
                PHP_EOL,
                $request['header']['Authorization'],
                PHP_EOL,
                $request['header']['Accept'],
                PHP_EOL,
                $request['header']['Content-Type'],
                PHP_EOL,
                $url
            );
        }
        return $curl;
    }
}
