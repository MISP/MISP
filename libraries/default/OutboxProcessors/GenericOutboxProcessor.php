<?php
use Cake\ORM\TableRegistry;
use Cake\Filesystem\File;
use Cake\Utility\Inflector;
use Cake\Validation\Validator;
use Cake\View\ViewBuilder;
use Cake\Routing\Router;

interface GenericOutboxProcessorActionI
{
    public function create($requestData);
    public function process($requestID, $serverRequest, $outboxRequest);
    public function discard($requestID ,$requestData);
}

class GenericOutboxProcessor
{
    protected $Outbox;
    protected $registeredActions = [];
    protected $validator;
    protected $processingTemplate = '/genericTemplates/confirm';
    protected $processingTemplatesDirectory = ROOT . '/libraries/default/OutboxProcessors/templates';

    public function __construct($registerActions=false) {
        $this->Outbox = TableRegistry::getTableLocator()->get('Outbox');
        if ($registerActions) {
            $this->registerActionInProcessor();
        }
        $this->assignProcessingTemplate();
    }

    private function assignProcessingTemplate()
    {
        $processingTemplatePath = $this->getProcessingTemplatePath();
        $file = new File($this->processingTemplatesDirectory . DS . $processingTemplatePath);
        if ($file->exists()) {
            $this->processingTemplate = str_replace('.php', '', $processingTemplatePath);
        }
        $file->close();
    }

    protected function updateProcessingTemplate($request)
    {
    }

    public function getRegisteredActions()
    {
        return $this->registeredActions;
    }
    public function getScope()
    {
        return $this->scope;
    }
    public function getDescription()
    {
        return $this->description ?? '';
    }

    protected function getProcessingTemplatePath()
    {
        return sprintf('%s/%s.php',
            $this->scope,
            $this->action
        );
    }

    public function getProcessingTemplate()
    {
        return $this->processingTemplate;
    }

    public function render($request=[], Cake\Http\ServerRequest $serverRequest)
    {
        $viewVariables = $this->getViewVariables($request);
        $this->updateProcessingTemplate($request);
        $processingTemplate = $this->getProcessingTemplate();
        $builder = new ViewBuilder();
        $builder->disableAutoLayout()
            ->setClassName('Monad')
            ->setTemplate($processingTemplate);
        $view = $builder->build($viewVariables);
        $view->setRequest($serverRequest);
        return $view->render();
    }

    protected function generateRequest($requestData)
    {
        $request = $this->Outbox->newEmptyEntity();
        $request = $this->Outbox->patchEntity($request, $requestData);
        if ($request->getErrors()) {
            throw new Exception(__('Could not create request.{0}Reason: {1}', PHP_EOL, json_encode($request->getErrors())), 1);
        }
        return $request;
    }

    protected function validateRequestData($requestData)
    {
        $errors = [];
        if (!isset($requestData['data'])) {
            $errors[] = __('No request data provided');
        }
        $validator = new Validator();
        if (method_exists($this, 'addValidatorRules')) {
            $validator = $this->addValidatorRules($validator);
            $errors = $validator->validate($requestData['data']);
        }
        if (!empty($errors)) {
            throw new Exception('Error while validating request data. ' . json_encode($errors), 1);
        }
    }

    protected function registerActionInProcessor()
    {
        foreach ($this->registeredActions as $i => $action) {
            $className = "{$action}Processor";
            $reflection = new ReflectionClass($className);
            if ($reflection->isAbstract() || $reflection->isInterface()) {
                throw new Exception(__('Cannot create instance of %s, as it is abstract or is an interface'));
            }
            $this->{$action} = $reflection->newInstance();
        }
    }

    protected function getViewVariablesConfirmModal($id, $title='', $question='', $actionName='')
    {
        return [
            'title' => !empty($title) ? $title : __('Process request {0}', $id),
            'question' => !empty($question) ? $question : __('Confirm request {0}', $id),
            'actionName' => !empty($actionName) ? $actionName : __('Confirm'),
            'path' => ['controller' => 'outbox', 'action' => 'process', $id]
        ];
    }

    public function getViewVariables($request)
    {
        return $this->getViewVariablesConfirmModal($request->id, '', '', '');
    }

    protected function genActionResult($data, $success, $message, $errors=[])
    {
        return [
            'data' => $data,
            'success' => $success,
            'message' => $message,
            'errors' => $errors,
        ];
    }

    public function genHTTPReply($controller, $processResult, $redirect=null)
    {
        $scope = $this->scope;
        $action = $this->action;
        if ($processResult['success']) {
            $message = !empty($processResult['message']) ? $processResult['message'] : __('Request {0} successfully processed.', $id);
            if ($controller->ParamHandler->isRest()) {
                $response = $controller->RestResponse->viewData($processResult, 'json');
            } else if ($controller->ParamHandler->isAjax()) {
                $response = $controller->RestResponse->ajaxSuccessResponse('OutboxProcessor', "{$scope}.{$action}", $processResult['data'], $message);
            } else {
                $controller->Flash->success($message);
                if (!is_null($redirect)) {
                    $response = $controller->redirect($redirect);
                } else {
                    $response = $controller->redirect(['action' => 'index']);
                }
            }
        } else {
            $message = !empty($processResult['message']) ? $processResult['message'] : __('Request {0} could not be processed.', $id);
            if ($controller->ParamHandler->isRest()) {
                $response = $controller->RestResponse->viewData($processResult, 'json');
            } else if ($controller->ParamHandler->isAjax()) {
                $response = $controller->RestResponse->ajaxFailResponse('OutboxProcessor', "{$scope}.{$action}", $processResult['data'], $message, $processResult['errors']);
            } else {
                $controller->Flash->error($message);
                if (!is_null($redirect)) {
                    $response = $controller->redirect($redirect);
                } else {
                    $response = $controller->redirect(['action' => 'index']);
                }
            }
        }

        return $response;
    }

    public function checkLoading()
    {
        return 'Assimilation successful!';
    }
    
    public function create($requestData)
    {
        $user_id = Router::getRequest()->getSession()->read('Auth.id');
        $requestData['scope'] = $this->scope;
        $requestData['action'] = $this->action;
        $requestData['description'] = $this->description;
        $requestData['user_id'] = $user_id;
        $request = $this->generateRequest($requestData);
        $savedRequest = $this->Outbox->createEntry($request);
        return $this->genActionResult(
            $savedRequest,
            $savedRequest !== false,
            __('{0} request for {1} created', $this->scope, $this->action),
            $request->getErrors()
        );
    }

    public function discard($id, $requestData)
    {
        $request = $this->Outbox->get($id);
        $this->Outbox->delete($request);
        return $this->genActionResult(
            [],
            true,
            __('{0}.{1} request #{2} discarded', $this->scope, $this->action, $id)
        );
    }
}
