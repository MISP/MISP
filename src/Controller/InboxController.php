<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Database\Expression\QueryExpression;
use Cake\Event\EventInterface;
use Cake\ORM\TableRegistry;
use Cake\Utility\Inflector;
use Cake\Utility\Hash;
use Cake\Utility\Text;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\ForbiddenException;


class InboxController extends AppController
{
    public $filterFields = ['scope', 'action', 'Inbox.created', 'severity', 'title', 'origin', 'message', 'Users.id', ['name' => 'Users.username', 'multiple' => true, 'options' => 'getAllUsername', 'select2' => true],];
    public $quickFilterFields = ['scope', 'action', ['title' => true], ['message' => true], 'origin'];
    public $containFields = ['Users'];

    public $paginate = [
        'order' => [
            'Inbox.created' => 'desc'
        ],
    ];

    public function beforeFilter(EventInterface $event)
    {
        parent::beforeFilter($event);
        $this->set('metaGroup', 'Administration');
    }


    public function index()
    {
        $this->CRUD->index([
            'filters' => $this->filterFields,
            'quickFilters' => $this->quickFilterFields,
            'contextFilters' => [
                'custom' => [
                    [
                        'default' => true,
                        'label' => __('My Notifications'),
                        'filterConditionFunction' => function ($query) {
                            return $query->where(function(QueryExpression $exp) {
                                return $exp->or(['user_id' => $this->ACL->getUser()['id']])
                                    ->isNull('user_id');
                            });
                        }
                    ],
                    [
                        'label' => __('User Registration'),
                        'filterConditionFunction' => function ($query) {
                            return $query->where([
                                'scope' => 'User',
                                'action' => 'Registration',
                            ]);
                        }
                    ],
                    [
                        'label' => 'severity:primary',
                        'viewElement' => 'bootstrapUI',
                        'viewElementParams' => [
                            'element' => 'badge',
                            'text' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_PRIMARY],
                            'variant' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_PRIMARY],
                        ],
                        'filterConditionFunction' => function ($query) {
                            return $query->where([
                                'severity' => $this->Inbox::SEVERITY_PRIMARY,
                            ]);
                        }
                    ],
                    [
                        'label' => 'severity:info',
                        'viewElement' => 'bootstrapUI',
                        'viewElementParams' => [
                            'element' => 'badge',
                            'text' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_INFO],
                            'variant' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_INFO],
                        ],
                        'filterConditionFunction' => function ($query) {
                            return $query->where([
                                'severity' => $this->Inbox::SEVERITY_INFO,
                            ]);
                        }
                    ],
                    [
                        'label' => 'severity:warning',
                        'viewElement' => 'bootstrapUI',
                        'viewElementParams' => [
                            'element' => 'badge',
                            'text' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_WARNING],
                            'variant' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_WARNING],
                        ],
                        'filterConditionFunction' => function ($query) {
                            return $query->where([
                                'severity' => $this->Inbox::SEVERITY_WARNING,
                            ]);
                        }
                    ],
                    [
                        'label' => 'severity:danger',
                        'viewElement' => 'bootstrapUI',
                        'viewElementParams' => [
                            'element' => 'badge',
                            'text' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_DANGER],
                            'variant' => $this->Inbox->severityVariant[$this->Inbox::SEVERITY_DANGER],
                        ],
                        'filterConditionFunction' => function ($query) {
                            return $query->where([
                                'severity' => $this->Inbox::SEVERITY_DANGER,
                            ]);
                        }
                    ],
                ],
            ],
            'contain' => $this->containFields
        ]);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function filtering()
    {
        $this->CRUD->filtering();
    }

    public function view($id)
    {
        $this->CRUD->view($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function delete($id=false)
    {
        if ($this->request->is('post')) { // cannot rely on CRUD's delete as inbox's processor discard function is responsible to handle their messages
            $ids = $this->CRUD->getIdsOrFail($id);
            $discardSuccesses = 0;
            $discardResults = [];
            $discardErrors = [];
            foreach ($ids as $id) {
                $request = $this->Inbox->get($id, ['contain' => ['Users' => ['Individuals' => ['Alignments' => 'Organisations']]]]);
                $this->inboxProcessors = TableRegistry::getTableLocator()->get('InboxProcessors');
                $processor = $this->inboxProcessors->getProcessor($request->scope, $request->action);
                $discardResult = $processor->discard($id, $request);
                $discardResults[] = $discardResult;
                if ($discardResult['success']) {
                    $discardSuccesses++;
                } else {
                    $discardErrors[] = $discardResult;
                }
            }
            if (count($ids) == 1) {
                return $processor->genHTTPReply($this, $discardResult);
            } else {
                $success = $discardSuccesses == count($ids);
                $message = __('{0} {1} have been discarded.',
                    $discardSuccesses == count($ids) ? __('All') : sprintf('%s / %s', $discardSuccesses, count($ids)),
                    sprintf('%s %s', Inflector::singularize($this->Inbox->getAlias()), __('messages'))
                );
                $this->CRUD->setResponseForController('delete', $success, $message, $discardResults, $discardResults);
                $responsePayload = $this->CRUD->getResponsePayload();
                if (!empty($responsePayload)) {
                    return $responsePayload;
                }
            }
        }
        $this->set('deletionTitle', __('Discard message'));
        if (!empty($id)) {
            $this->set('deletionText', __('Are you sure you want to discard message #{0}?', $id));
        } else {
            $this->set('deletionText', __('Are you sure you want to discard the selected message?'));
        }
        $this->set('deletionConfirm', __('Discard'));
        $this->CRUD->delete($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function process($id)
    {
        $request = $this->Inbox->get($id, ['contain' => ['Users' => ['Individuals' => ['Alignments' => 'Organisations']]]]);
        $scope = $request->scope;
        $action = $request->action;
        $this->InboxProcessors = TableRegistry::getTableLocator()->get('InboxProcessors');
        $processor = $this->InboxProcessors->getProcessor($scope, $action);
        if ($this->request->is('post')) {
            $processResult = $processor->process($id, $this->request->getData(), $request);
            return $processor->genHTTPReply($this, $processResult);
        } else {
            $renderedView = $processor->render($request, $this->request);
            return $this->response->withStringBody($renderedView);
        }
    }

    public function listProcessors()
    {
        $this->inboxProcessors = TableRegistry::getTableLocator()->get('InboxProcessors');
        $processors = $this->inboxProcessors->listProcessors();
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($processors, 'json');
        }
        $data = [];
        foreach ($processors as $scope => $scopedProcessors) {
            foreach ($scopedProcessors as $processor) {
                $data[] = [
                    'enabled' => $processor->enabled,
                    'scope' => $scope,
                    'action' => $processor->action,
                    'description' => isset($processor->getDescription) ? $processor->getDescription() : null,
                    'notice' => $processor->notice ?? null,
                    'error' => $processor->error ?? null,
                ];
            }
        }
        $this->set('data', $data);
    }

    public function createEntry($scope, $action)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('Only POST method is accepted'));
        }
        $entryData = [
            'origin' => $this->request->clientIp(),
            'user_id' => $this->ACL->getUser()['id'],
        ];
        $entryData['data'] = $this->request->getData() ?? [];
        $this->inboxProcessors = TableRegistry::getTableLocator()->get('InboxProcessors');
        $processor = $this->inboxProcessors->getProcessor($scope, $action);
        $creationResult = $this->inboxProcessors->createInboxEntry($processor, $entryData);
        return $processor->genHTTPReply($this, $creationResult);
    }

    private function validateLocalToolRequestEntry($entryData)
    {
        if (empty($entryData['data']['connectorName']) || empty($entryData['data']['cerebrateURL'])) {
            throw new MethodNotAllowedException(__('Could not create entry. Tool name or URL is missing'));
        }
    }
}
