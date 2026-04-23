<?php
App::uses('AppController', 'Controller');
App::uses('CakeText', 'Utility');
App::uses('EventTemplateDependencies', 'Tools');
App::uses('EventTemplateExporter', 'Tools');
App::uses('EventTemplateImporter', 'Tools');
App::uses('EventTemplateImportException', 'Tools');
App::uses('EventTemplateInstantiator', 'Tools');
App::uses('EventTemplateInstantiationException', 'Tools');
App::uses('EventTemplateValidator', 'Tools');
App::uses('JsonTool', 'Tools');

/**
 * EventTemplatesController — v2 event templating system.
 *
 * Exposes the REST endpoints listed in docs/dev/event-templating-prd.md §9
 * and the corresponding HTML surfaces. Authorisation follows PRD §8:
 *
 *   - Read  (index/view/export/instantiate): own-org templates OR templates
 *     with distribution = 1 (community). Site admins see every template.
 *   - Write (add/edit/delete/duplicate/import/validate_definition): requires
 *     perm_template (enforced via ACLComponent) AND — for row-scoped actions
 *     — that the template's org_id matches the caller's. Site admins can
 *     write any template.
 *   - Use   (instantiate): perm_add (enforced via ACLComponent) combined with
 *     read visibility on the template.
 *
 * @property EventTemplate $EventTemplate
 */
class EventTemplatesController extends AppController
{
    public $paginate = array(
        'limit' => 60,
        'order' => array('EventTemplate.modified' => 'desc'),
        'recursive' => -1,
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
        $missing = EventTemplateDependencies::missing();
        if (!empty($missing)) {
            return $this->__renderDependencyMissing($missing);
        }
    }

    public function index()
    {
        $params = array(
            'filters' => array(
                'EventTemplate.name', 'EventTemplate.uuid',
                'EventTemplate.description', 'EventTemplate.active',
                'EventTemplate.org_id', 'searchall',
            ),
            'quickFilters' => array(
                'EventTemplate.name', 'EventTemplate.uuid',
                'EventTemplate.description',
            ),
            'quickFilterParameter' => 'searchall',
            'conditions' => $this->__visibilityConditions(),
            'contain' => array(
                'Organisation' => array(
                    'fields' => array(
                        'Organisation.id',
                        'Organisation.name',
                        'Organisation.uuid',
                    ),
                ),
                'CreatorUser' => array(
                    'fields' => array('CreatorUser.id', 'CreatorUser.email'),
                ),
            ),
            'order' => array('EventTemplate.modified' => 'DESC'),
        );
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('list', $this->viewVars['data']);
    }

    public function view($id)
    {
        $id = $this->__resolveId($id);
        $params = array(
            'conditions' => $this->__visibilityConditions(),
            'contain' => array(
                'Organisation' => array(
                    'fields' => array(
                        'Organisation.id',
                        'Organisation.name',
                        'Organisation.uuid',
                    ),
                ),
                'CreatorUser' => array(
                    'fields' => array('CreatorUser.id', 'CreatorUser.email'),
                ),
                'EventTemplateObjectDependency',
            ),
        );
        $this->CRUD->view($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
    }

    public function delete($id)
    {
        $id = $this->__resolveId($id);
        $params = array(
            'conditions' => $this->__writeConditions(),
        );
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function add()
    {
        if (!$this->request->is('post') && !$this->request->is('put')) {
            $this->set('title_for_layout', __('Add Event Template'));
            $this->render('add');
            return;
        }

        $input = $this->__unwrap($this->request->data);
        $row = array(
            'name' => isset($input['name']) ? $input['name'] : '',
            'description' => isset($input['description'])
                ? $input['description']
                : null,
            'distribution' => isset($input['distribution'])
                ? (int)$input['distribution']
                : 0,
            'active' => (!array_key_exists('active', $input) || $input['active'])
                ? 1
                : 0,
            'org_id' => (int)$this->Auth->user('org_id'),
            'creator_user_id' => (int)$this->Auth->user('id'),
            'definition' => isset($input['definition'])
                ? $input['definition']
                : null,
        );
        if (!empty($input['uuid'])) {
            $row['uuid'] = strtolower((string)$input['uuid']);
        }

        $this->EventTemplate->create();
        $saved = $this->EventTemplate->save(array('EventTemplate' => $row));
        if (!$saved) {
            return $this->__handleSaveFailure('add', false, array(
                'EventTemplate' => $row,
            ));
        }

        $savedId = (int)$this->EventTemplate->id;
        return $this->__respondWithSavedRow('add', $savedId);
    }

    public function edit($id)
    {
        $id = $this->__resolveId($id);
        $existing = $this->__fetchForWrite($id);

        if (!$this->request->is('post') && !$this->request->is('put')) {
            $this->set('data', $existing);
            $this->set('id', $id);
            $this->set('title_for_layout', __('Edit Event Template'));
            $this->render('edit');
            return;
        }

        $input = $this->__unwrap($this->request->data);
        // Immutable fields are never accepted from the caller on edit.
        foreach (array('id', 'uuid', 'org_id', 'creator_user_id', 'created') as $k) {
            unset($input[$k]);
        }
        // CakePHP's beforeValidate bumps version automatically; ignore any
        // version the caller tries to set to avoid skipping numbers.
        unset($input['version']);

        $row = array_merge($existing['EventTemplate'], $input);
        $row['id'] = $id;
        $this->EventTemplate->id = $id;
        $saved = $this->EventTemplate->save(array('EventTemplate' => $row));
        if (!$saved) {
            return $this->__handleSaveFailure('edit', $id, array(
                'EventTemplate' => $row,
            ));
        }
        return $this->__respondWithSavedRow('edit', $id);
    }

    public function export($id)
    {
        $id = $this->__resolveId($id);
        $source = $this->__fetchForRead($id);
        $exporter = new EventTemplateExporter();
        $payload = $exporter->export($source);
        $filename = sprintf(
            'event-template-%s.json',
            $source['EventTemplate']['uuid']
        );
        return $this->RestResponse->viewData(
            $payload,
            'json',
            false,
            true,
            $filename
        );
    }

    public function import()
    {
        if (!$this->request->is('post') && !$this->request->is('put')) {
            $this->set('title_for_layout', __('Import Event Template'));
            $this->render('import');
            return;
        }

        $mode = isset($this->request->query['mode'])
            ? (string)$this->request->query['mode']
            : 'fail';
        $payload = $this->__readImportPayload();
        if (!is_array($payload)) {
            $errors = array(__('Could not parse import payload as JSON.'));
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveFailResponse(
                    'EventTemplates', 'import', false, $errors, 'json'
                );
            }
            $this->Flash->error($errors[0]);
            $this->render('import');
            return;
        }

        $importer = new EventTemplateImporter();
        try {
            $result = $importer->import(
                $payload,
                $this->Auth->user(),
                array('mode' => $mode)
            );
        } catch (EventTemplateImportException $e) {
            $errors = array_merge(array($e->getMessage()), $e->getErrors());
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveFailResponse(
                    'EventTemplates', 'import', false, $errors, 'json'
                );
            }
            $this->Flash->error($e->getMessage());
            $this->set('errors', $errors);
            $this->render('import');
            return;
        }

        if ($this->IndexFilter->isRest()) {
            return $this->RestResponse->viewData($result, 'json');
        }
        $this->Flash->success(__('Event template imported.'));
        $this->redirect(array(
            'action' => 'view',
            $result['event_template_id'],
        ));
    }

    private function __readImportPayload()
    {
        // Prefer an uploaded file when present — this is the UI path.
        if (!empty($this->request->data['file']['tmp_name'])
            && is_uploaded_file($this->request->data['file']['tmp_name'])
        ) {
            $content = file_get_contents(
                $this->request->data['file']['tmp_name']
            );
            $decoded = JsonTool::decode($content);
            return is_array($decoded) ? $decoded : null;
        }
        // CakePHP auto-parses application/json bodies into request->data.
        if (is_array($this->request->data) && !empty($this->request->data)) {
            return $this->request->data;
        }
        // Fall back to the raw body for clients that post JSON without a
        // Content-Type header CakePHP recognises.
        $raw = $this->request->input();
        if (is_string($raw) && $raw !== '') {
            $decoded = JsonTool::decode($raw);
            if (is_array($decoded)) {
                return $decoded;
            }
        }
        return null;
    }

    public function duplicate($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(
                __('Duplicate requires POST.')
            );
        }
        $id = $this->__resolveId($id);
        $source = $this->__fetchForRead($id);

        $definition = $source['EventTemplate']['definition'];
        if (!is_array($definition)) {
            $decoded = JsonTool::decode((string)$definition);
            $definition = is_array($decoded) ? $decoded : array();
        }

        $input = $this->__unwrap($this->request->data);
        $newUuid = strtolower(CakeText::uuid());
        // Keep the JSON's internal uuid aligned with the row uuid so the two
        // never drift for a newly-duplicated row.
        $definition['uuid'] = $newUuid;
        $newName = !empty($input['name'])
            ? (string)$input['name']
            : sprintf('%s %s', $source['EventTemplate']['name'], __('(copy)'));

        $row = array(
            'uuid' => $newUuid,
            'name' => $newName,
            'description' => $source['EventTemplate']['description'],
            // Default a freshly-duplicated template back to org-only; the
            // caller can re-expose it explicitly via edit if they want the
            // community copy to also be community-visible.
            'distribution' => 0,
            'active' => 1,
            'org_id' => (int)$this->Auth->user('org_id'),
            'creator_user_id' => (int)$this->Auth->user('id'),
            'definition' => $definition,
        );

        $this->EventTemplate->create();
        $saved = $this->EventTemplate->save(array('EventTemplate' => $row));
        if (!$saved) {
            return $this->__handleSaveFailure('duplicate', $id, array(
                'EventTemplate' => $row,
            ));
        }
        return $this->__respondWithSavedRow(
            'duplicate',
            (int)$this->EventTemplate->id
        );
    }

    public function instantiate($id)
    {
        if (!$this->request->is('post') && !$this->request->is('put')) {
            throw new MethodNotAllowedException(
                __('Instantiate requires POST.')
            );
        }
        $id = $this->__resolveId($id);
        $source = $this->__fetchForRead($id);

        $definition = $source['EventTemplate']['definition'];
        if (!is_array($definition)) {
            $decoded = JsonTool::decode((string)$definition);
            $definition = is_array($decoded) ? $decoded : array();
        }

        $input = $this->__unwrap($this->request->data);
        $values = (isset($input['values']) && is_array($input['values']))
            ? $input['values']
            : $input;

        $instantiator = new EventTemplateInstantiator();
        try {
            $result = $instantiator->instantiate(
                $definition,
                $values,
                $this->Auth->user()
            );
        } catch (EventTemplateInstantiationException $e) {
            $errors = array_merge(array($e->getMessage()), $e->getErrors());
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveFailResponse(
                    'EventTemplates', 'instantiate', $id, $errors, 'json'
                );
            }
            $this->Flash->error($e->getMessage());
            $this->redirect(array('action' => 'view', $id));
            return;
        }

        if ($this->IndexFilter->isRest()) {
            return $this->RestResponse->viewData($result, 'json');
        }
        $this->Flash->success(__('Event created from template.'));
        $this->redirect(array(
            'controller' => 'events',
            'action' => 'view',
            $result['event_id'],
        ));
    }

    public function validate_definition()
    {
        if (!$this->request->is('post') && !$this->request->is('put')) {
            throw new MethodNotAllowedException(
                __('validate_definition requires POST.')
            );
        }
        $input = $this->__unwrap($this->request->data);
        $definition = (isset($input['definition']) && is_array($input['definition']))
            ? $input['definition']
            : $input;

        $validator = new EventTemplateValidator();
        $errors = $validator->validate($definition);
        $payload = array(
            'valid' => empty($errors),
            'errors' => array_values($errors),
        );
        if ($this->IndexFilter->isRest()) {
            return $this->RestResponse->viewData($payload, 'json');
        }
        $this->set('result', $payload);
        $this->render('validate_definition');
    }

    private function __unwrap($data)
    {
        if (is_array($data) && isset($data['EventTemplate'])
            && is_array($data['EventTemplate'])
        ) {
            return $data['EventTemplate'];
        }
        return is_array($data) ? $data : array();
    }

    private function __fetchForRead($id)
    {
        $row = $this->EventTemplate->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'AND' => array(
                    array('EventTemplate.id' => $id),
                    $this->__visibilityConditions(),
                ),
            ),
        ));
        if (empty($row)) {
            throw new NotFoundException(__('Invalid event template.'));
        }
        return $row;
    }

    private function __fetchForWrite($id)
    {
        $row = $this->EventTemplate->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'AND' => array(
                    array('EventTemplate.id' => $id),
                    $this->__writeConditions(),
                ),
            ),
        ));
        if (empty($row)) {
            throw new NotFoundException(__('Invalid event template.'));
        }
        return $row;
    }

    private function __handleSaveFailure($action, $id, array $formData)
    {
        $errors = $this->EventTemplate->validationErrors;
        if ($this->IndexFilter->isRest()) {
            return $this->RestResponse->saveFailResponse(
                'EventTemplates',
                $action,
                $id,
                $errors,
                'json'
            );
        }
        $this->Flash->error(__('Event template could not be saved.'));
        $this->set('data', $formData);
        $this->set('errors', $errors);
        $this->render($action);
    }

    private function __respondWithSavedRow($action, $id)
    {
        $fresh = $this->EventTemplate->find('first', array(
            'conditions' => array('EventTemplate.id' => $id),
            'recursive' => -1,
        ));
        if ($this->IndexFilter->isRest()) {
            return $this->RestResponse->viewData($fresh, 'json');
        }
        $this->Flash->success(__('Event template saved.'));
        $this->redirect(array('action' => 'view', $id));
    }

    /**
     * Resolve a route parameter to an integer id. Accepts either an integer
     * id or a template uuid. An unknown uuid returns 404 rather than 0, so
     * the caller never receives an invalid id.
     */
    private function __resolveId($idOrUuid)
    {
        if (is_string($idOrUuid) && Validation::uuid($idOrUuid)) {
            $row = $this->EventTemplate->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'EventTemplate.uuid' => strtolower($idOrUuid),
                ),
                'fields' => array('EventTemplate.id'),
            ));
            if (empty($row)) {
                throw new NotFoundException(__('Invalid event template.'));
            }
            return (int)$row['EventTemplate']['id'];
        }
        if (!is_numeric($idOrUuid)) {
            throw new NotFoundException(__('Invalid event template id.'));
        }
        return (int)$idOrUuid;
    }

    /**
     * PRD §8 read scope. Site admin sees every row; other users see their
     * own org's templates plus any template marked as community-distributed.
     */
    private function __visibilityConditions()
    {
        if ($this->_isSiteAdmin()) {
            return array();
        }
        return array(
            'OR' => array(
                'EventTemplate.org_id' => (int)$this->Auth->user('org_id'),
                'EventTemplate.distribution' => 1,
            ),
        );
    }

    /**
     * PRD §8 write scope. perm_template is enforced centrally via ACL; this
     * helper adds the row-level "same org" requirement. Community-distributed
     * templates are readable cross-org but not writable cross-org — only
     * members of the owning org (and site admins) can mutate them.
     */
    private function __writeConditions()
    {
        if ($this->_isSiteAdmin()) {
            return array();
        }
        return array(
            'EventTemplate.org_id' => (int)$this->Auth->user('org_id'),
        );
    }

    /**
     * Composer deps guard — PRD §11.2. Called from beforeFilter when any
     * required package is not loadable. Produces a clean admin-facing page
     * for HTML requests and a structured 503 envelope for REST, rather than
     * letting the raw exception surface.
     */
    private function __renderDependencyMissing(array $missing)
    {
        $missing = array_values($missing);
        $message = sprintf(
            __('Event templating is unavailable on this instance because the following PHP package(s) are not installed: %s. Ask your MISP administrator to run `cd app && composer install` on the MISP host.'),
            implode(', ', $missing)
        );
        if ($this->IndexFilter->isRest()) {
            return new CakeResponse(array(
                'body' => JsonTool::encode(array(
                    'name' => 'Event templating unavailable',
                    'message' => $message,
                    'missing_dependencies' => $missing,
                    'url' => $this->here,
                )),
                'status' => 503,
                'type' => 'json',
            ));
        }
        $this->set('message', $message);
        $this->set('missing', $missing);
        $this->set('title_for_layout', __('Event templating unavailable'));
        return $this->render('dependency_missing');
    }
}
