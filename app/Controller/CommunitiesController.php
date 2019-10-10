<?php
App::uses('AppController', 'Controller');

class CommunitiesController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        parent::beforeFilter();
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999
    );

    public function index()
    {
        $paramsToHarvest = array('context', 'value');
        foreach ($paramsToHarvest as $param) {
            if (!empty($this->params['named'][$param])) {
                ${$param} = $this->params['named'][$param];
            } else if ($this->request->is('post') && !empty($this->request->data[$param])) {
                ${$param} = trim($this->request->data[$param]);
            } else if ($param === 'context') {
                ${$param} = 'vetted';
            }
        }
        $filterData = array(
            'request' => $this->request,
            'paramArray' => array('context', 'value'),
            'named_params' => $this->params['named']
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception);
        if (empty($filters['context'])) {
            $filters['context'] = 'vetted';
        }
        if (!empty($value)) {
            $value = strtolower($value);
        } else {
            $value = false;
        }
        $community_list = $this->Community->getCommunityList($context, $value);

        //foreach ($community)
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($community_list, $this->response->type());
        }
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        $customPagination->truncateAndPaginate($community_list, $this->params, $this->modelClass, true);
        $this->set('community_list', $community_list);
        $this->set('context', $filters['context']);
        $this->set('passedArgs', json_encode($this->passedArgs, true));
    }

    public function view($id)
    {

        $community = $this->Community->getCommunity($id);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($community, $this->response->type());
        } else {
            $this->set('community', $community);
        }
    }

    public function requestAccess($id)
    {
        $community = $this->Community->getCommunity($id);
        $this->loadModel('User');
        $gpgkey = $this->User->find('first', array(
            'conditions' => array('User.id' => $this->Auth->user('id')),
            'recursive' => -1,
            'fields' => array('User.gpgkey')
        ));
        if (!empty($gpgkey['User']['gpgkey'])) {
            $gpgkey = $gpgkey['User']['gpgkey'];
        } else {
            $gpgkey = '';
        }
        if (!$this->request->is('post')) {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Communities', 'requestAccess', false, $this->response->type());
            }
            $this->request->data['Server']['email'] = $this->Auth->user('email');
            $this->request->data['Server']['org_name'] = $this->Auth->user('Organisation')['name'];
            $this->request->data['Server']['org_uuid'] = $this->Auth->user('Organisation')['uuid'];
            $this->request->data['Server']['gpgkey'] = $gpgkey;
        } else {
            if (empty($this->request->data['Server'])) {
                $this->request->data = array('Server' => $this->request->data);
            }
            $body = sprintf(
                'To whom it may concern,

On behalf of my organisation (%s - %s),
I would hereby like to request %saccess to your MISP community:
%s

A brief description of my organisation:
%s

My e-mail address that I wish to use as my username:
%s
%s%s

Thank you in advance!',
                empty($this->request->data['Server']['org_name']) ? $this->Auth->user('Organisation')['name'] : $this->request->data['Server']['org_name'],
                empty($this->request->data['Server']['org_uuid']) ? $this->Auth->user('Organisation')['uuid'] : $this->request->data['Server']['org_uuid'],
                empty($this->request->data['Server']['sync']) ? '' : 'synchronisation ',
                $community['name'],
                empty($this->request->data['Server']['org_description']) ? '' : $this->request->data['Server']['org_description'],
                empty($this->request->data['Server']['email']) ? '' : $this->request->data['Server']['email'],
                empty($this->request->data['Server']['message']) ? '' : sprintf(
                    '%sAdditional information:%s%s%s',
                    PHP_EOL,
                    PHP_EOL,
                    $this->request->data['Server']['message'],
                    PHP_EOL
                ),
                !empty($this->request->data['Server']['anonymise']) ? '' : sprintf(
                    '%sServer used to issue the request%sServer url: %sServer uuid: %sServer version: %s',
                    PHP_EOL,
                    PHP_EOL,
                    (empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl')) . PHP_EOL,
                    Configure::read('MISP.uuid') . PHP_EOL,
                    $this->mispVersion . PHP_EOL
                )
            );
            $imgPath = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS;
            $possibleFields = array('id', 'name');
            $image = false;
            App::uses('File', 'Utility');
            foreach ($possibleFields as $field) {
                if (isset($options[$field])) {
                    $file = new File($imgPath . $options[$field] . 'png');
                    if ($file->exists()) {
                        $image = $file->read();
                        break;
                    }
                }
            }
            if (!isset($this->request->data['Server']['gpgkey'])) {
                $this->request->data['Server']['gpgkey'] = $gpgkey;
            }
            if (!empty($image)) {
                $params['attachments']['logo.png'] = $image;
            }
            if (!empty($this->request->data['Server']['gpgkey'])) {
                $params['attachments']['requestor.asc'] = $this->request->data['Server']['gpgkey'];
            }
            $params = array();
            $params['to'] = $community['email'];
            $params['reply-to'] = empty($this->request->data['Server']['email']) ? $this->Auth->user('email') : $this->request->data['Server']['email'];
            $params['requestor_gpgkey'] = empty($this->request->data['Server']['gpgkey']) ? $gpgkey : $this->request->data['Server']['gpgkey'];
            $params['gpgkey'] = $community['pgp_key'];
            $params['body'] = $body;
            $params['subject'] = '[' . $community['name'] . '] Requesting MISP access';
            $params['mock'] = !empty($this->request->data['Server']['mock']) ? $this->request->data['Server']['mock'] : 0;
            if (!empty(Configure::read('MISP.disable_emailing'))) {
                $params['mock'] = 1;
            }
            $result = $this->User->sendEmailExternal($this->Auth->user(), $params);
            $message = $result ? __('Request sent.') : __('Something went wrong and the request could not be sent.');
            if ($this->_isRest()) {
                if ($result === true) {
                    return $this->RestResponse->saveSuccessResponse('Communities', 'requestAccess', $id, false, $message);
                } elseif ($result) {
                    return $this->RestResponse->viewData($result);
                } else {
                    return $this->RestResponse->saveFailResponse('Communities', 'requestAccess', false, $message);
                }
            } else {
                if ($result === true) {
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'communities', 'action' => 'view', $id));
                } elseif ($result) {
                    $this->set('result', $result);
                    if (empty($this->request->data['Server']['mock'])) {
                        $this->Flash->error(__('The message could not be sent (either because e-mailing is disabled or because encryption is misconfigured), however, you can view the e-mail that would have been sent below. Feel free to send it manually.'));
                    }
                    $this->render('request_access_email');
                } else {
                    $this->Flash->error($message);
                    $this->redirect(array('controller' => 'communities', 'action' => 'view', $id));
                }
            }
            if (!empty($this->request->data['Server']['mock'])) {
                $this->set('mock', $this->request->data['Server']['mock']);
            }
        }
        $this->set('community', $community);
    }
}
