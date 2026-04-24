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
    public $components = array('RequestHandler', 'Session');

    public $helpers = array('EventTemplateMarkdown');

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
            $this->__setBuilderConfig();
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
            $this->__setBuilderConfig();
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
        // CakePHP's tinyint(1) read-side coercion hands back PHP booleans
        // for distribution/active; the model's inList validator checks
        // strictly and would reject them on re-save. Coerce back to int.
        if (array_key_exists('distribution', $row)) {
            $row['distribution'] = (int)$row['distribution'];
        }
        if (array_key_exists('active', $row)) {
            $row['active'] = (int)$row['active'];
        }
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
        // $raw=false so RestResponse json-encodes the array body; the
        // resulting JSON IS the export document — no MISP envelope is
        // added for top-level arrays/objects.
        return $this->RestResponse->viewData(
            $payload,
            'json',
            false,
            false,
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

        // Accept `mode` from either the query string (REST clients) or
        // the POST body (the Phase-2 import form, which has no JS).
        $mode = 'fail';
        if (isset($this->request->query['mode'])) {
            $mode = (string)$this->request->query['mode'];
        } elseif (is_array($this->request->data)
            && !empty($this->request->data['EventTemplate']['mode'])
        ) {
            $mode = (string)$this->request->data['EventTemplate']['mode'];
        } elseif (is_array($this->request->data)
            && !empty($this->request->data['mode'])
        ) {
            $mode = (string)$this->request->data['mode'];
        }
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
        $data = $this->request->data;

        // UI multipart form path: uploaded file wins if present.
        $fileMeta = isset($data['EventTemplate']['submittedjson'])
            ? $data['EventTemplate']['submittedjson']
            : (isset($data['file']) ? $data['file'] : null);
        if (is_array($fileMeta)
            && !empty($fileMeta['tmp_name'])
            && is_uploaded_file($fileMeta['tmp_name'])
        ) {
            $content = file_get_contents($fileMeta['tmp_name']);
            $decoded = JsonTool::decode($content);
            return is_array($decoded) ? $decoded : null;
        }

        // UI form path: textarea paste in the `json` field.
        $pasted = null;
        if (isset($data['EventTemplate']['json'])
            && is_string($data['EventTemplate']['json'])
            && trim($data['EventTemplate']['json']) !== ''
        ) {
            $pasted = $data['EventTemplate']['json'];
        } elseif (isset($data['json'])
            && is_string($data['json'])
            && trim($data['json']) !== ''
        ) {
            $pasted = $data['json'];
        }
        if ($pasted !== null) {
            $decoded = JsonTool::decode($pasted);
            return is_array($decoded) ? $decoded : null;
        }

        // REST path: request->data is the export document itself. We
        // detect this by the characteristic `_meta` or `template` keys,
        // to avoid accidentally treating a multipart form post (with
        // just `mode` filled in and no payload) as a valid import.
        if (is_array($data)
            && (isset($data['_meta']) || isset($data['template']))
        ) {
            return $data;
        }

        // Fallback: raw body for clients that post JSON without a
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
        $id = $this->__resolveId($id);
        $source = $this->__fetchForRead($id);

        $definition = $source['EventTemplate']['definition'];
        if (!is_array($definition)) {
            $decoded = JsonTool::decode((string)$definition);
            $definition = is_array($decoded) ? $decoded : array();
        }

        // GET renders the user form; POST runs the instantiator.
        if (!$this->request->is('post') && !$this->request->is('put')) {
            $this->__renderUserForm($source, $definition, false);
            return;
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

    public function preview($id)
    {
        $id = $this->__resolveId($id);
        $source = $this->__fetchForRead($id);
        $definition = $source['EventTemplate']['definition'];
        if (!is_array($definition)) {
            $decoded = JsonTool::decode((string)$definition);
            $definition = is_array($decoded) ? $decoded : array();
        }
        $this->__renderUserForm($source, $definition, true);
    }

    /**
     * Shared helper for both instantiate (GET) and preview. Fetches
     * the object-template relation specs referenced by the template's
     * object_field elements, sets up the view vars, and renders the
     * user_form (or preview, depending on $isPreview).
     */
    private function __renderUserForm(array $source, array $definition, $isPreview)
    {
        $relationSpecs = $this->__collectObjectRelationSpecs($definition);
        $this->set('data', $source);
        $this->set('id', (int)$source['EventTemplate']['id']);
        $this->set('definition', $definition);
        $this->set('objectRelationSpecs', $relationSpecs);
        $this->set('isPreview', (bool)$isPreview);
        $this->set('title_for_layout',
            $isPreview
                ? __('Preview — %s', $source['EventTemplate']['name'])
                : __('Create event from template — %s', $source['EventTemplate']['name'])
        );
        $this->render($isPreview ? 'preview' : 'user_form');
    }

    /**
     * For every object_field element in the definition, looks up the
     * matching ObjectTemplate at the pinned version and returns its
     * relations (object_relation, type, description, multiple,
     * sane_default, ui-priority) keyed by the element's stable id.
     * Missing or version-mismatched templates are flagged so the
     * form can render a friendly error instead of silently dropping
     * the element.
     */
    private function __collectObjectRelationSpecs(array $definition)
    {
        $out = array();
        if (!isset($definition['structure']) || !is_array($definition['structure'])) {
            return $out;
        }
        $this->loadModel('ObjectTemplate');
        foreach ($definition['structure'] as $el) {
            if (!is_array($el) || ($el['type'] ?? '') !== 'object_field') {
                continue;
            }
            $id = $el['id'] ?? null;
            $ot = $el['object_template'] ?? array();
            $uuid = isset($ot['uuid']) ? strtolower((string)$ot['uuid']) : '';
            $pinned = isset($ot['pinned_version']) ? (int)$ot['pinned_version'] : 0;
            if ($id === null || $uuid === '' || $pinned === 0) {
                continue;
            }
            $row = $this->ObjectTemplate->find('first', array(
                'recursive' => -1,
                'contain' => array('ObjectTemplateElement'),
                'conditions' => array(
                    'ObjectTemplate.uuid' => $uuid,
                    'ObjectTemplate.version >=' => $pinned,
                    'ObjectTemplate.active' => true,
                ),
                'order' => array('ObjectTemplate.version' => 'ASC'),
            ));
            if (empty($row)) {
                $out[$id] = array(
                    'missing' => true,
                    'uuid' => $uuid,
                    'pinned_version' => $pinned,
                    'relations' => array(),
                );
                continue;
            }
            $rels = array();
            foreach ($row['ObjectTemplateElement'] as $rel) {
                $rels[] = array(
                    'object_relation' => (string)$rel['object_relation'],
                    'type' => (string)$rel['type'],
                    'description' => (string)($rel['description'] ?? ''),
                    'multiple' => !empty($rel['multiple']),
                    'ui_priority' => (int)($rel['ui-priority'] ?? 0),
                );
            }
            usort($rels, function ($a, $b) {
                return $b['ui_priority'] - $a['ui_priority'];
            });

            // Apply the template creator's per-relation whitelist:
            // a non-empty `relations[]` on the element restricts the
            // user form to just those relations. Empty/absent = show
            // every relation the object template defines.
            if (isset($el['relations']) && is_array($el['relations']) && !empty($el['relations'])) {
                $wanted = array();
                foreach ($el['relations'] as $rel) {
                    if (is_array($rel) && !empty($rel['object_relation'])) {
                        $wanted[(string)$rel['object_relation']] = true;
                    }
                }
                if (!empty($wanted)) {
                    $rels = array_values(array_filter($rels, function ($r) use ($wanted) {
                        return isset($wanted[$r['object_relation']]);
                    }));
                }
            }

            // requirements is a JSON column carrying `required` and/or
            // `requiredOneOf` lists. Decode defensively; an empty/null
            // column just means no constraints.
            $requirements = array();
            if (!empty($row['ObjectTemplate']['requirements'])) {
                $decoded = is_array($row['ObjectTemplate']['requirements'])
                    ? $row['ObjectTemplate']['requirements']
                    : json_decode((string)$row['ObjectTemplate']['requirements'], true);
                if (is_array($decoded)) {
                    $requirements = $decoded;
                }
            }

            $out[$id] = array(
                'missing' => false,
                'uuid' => $uuid,
                'pinned_version' => $pinned,
                'found_version' => (int)$row['ObjectTemplate']['version'],
                'meta_category' => $row['ObjectTemplate']['meta-category'] ?? '',
                'template_description' => $row['ObjectTemplate']['description'] ?? '',
                'relations' => $rels,
                'requirements' => $requirements,
            );
        }
        return $out;
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
    /**
     * Loads the data needed by the default-theme builder shell —
     * attribute category→types mapping + installed object templates —
     * and hands it to the view so the per-element-type properties
     * partials can render populated dropdowns without further AJAX.
     * Called from the GET paths of add() and edit().
     */
    private function __setBuilderConfig()
    {
        $this->loadModel('MispAttribute');
        $categories = array();
        foreach ($this->MispAttribute->categoryDefinitions as $name => $def) {
            $categories[$name] = isset($def['types']) ? array_values($def['types']) : array();
        }
        ksort($categories);
        $this->set('attributeCategoryDefinitions', $categories);

        $this->loadModel('ObjectTemplate');
        $templates = $this->ObjectTemplate->find('all', array(
            'recursive' => -1,
            'conditions' => array('ObjectTemplate.active' => true),
            'fields' => array(
                'ObjectTemplate.uuid',
                'ObjectTemplate.name',
                'ObjectTemplate.version',
                'ObjectTemplate.meta-category',
                'ObjectTemplate.description',
            ),
            'order' => array('ObjectTemplate.name' => 'ASC'),
        ));
        $objectTemplates = array();
        foreach ($templates as $t) {
            $row = $t['ObjectTemplate'];
            $objectTemplates[] = array(
                'uuid' => (string)$row['uuid'],
                'name' => (string)$row['name'],
                'version' => (int)$row['version'],
                'meta_category' => (string)($row['meta-category'] ?? ''),
                'description' => (string)($row['description'] ?? ''),
            );
        }
        $this->set('objectTemplatesAvailable', $objectTemplates);

        $this->loadModel('Taxonomy');
        $taxonomyRows = $this->Taxonomy->find('all', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.enabled' => true),
            'fields' => array(
                'Taxonomy.namespace',
                'Taxonomy.description',
                'Taxonomy.version',
            ),
            'order' => array('Taxonomy.namespace' => 'ASC'),
        ));
        $taxonomies = array();
        foreach ($taxonomyRows as $r) {
            $t = $r['Taxonomy'];
            $taxonomies[] = array(
                'value' => (string)$t['namespace'],
                'label' => (string)$t['namespace'],
                'description' => (string)($t['description'] ?? ''),
            );
        }
        $this->set('taxonomiesAvailable', $taxonomies);

        $this->loadModel('Galaxy');
        $galaxyRows = $this->Galaxy->find('all', array(
            'recursive' => -1,
            'conditions' => array('Galaxy.enabled' => true),
            'fields' => array(
                'Galaxy.type',
                'Galaxy.description',
            ),
            'group' => array('Galaxy.type'),
            'order' => array('Galaxy.type' => 'ASC'),
        ));
        $galaxyTypes = array();
        $seenTypes = array();
        foreach ($galaxyRows as $r) {
            $t = $r['Galaxy']['type'];
            if ($t === null || $t === '' || isset($seenTypes[$t])) {
                continue;
            }
            $seenTypes[$t] = true;
            $galaxyTypes[] = array(
                'value' => (string)$t,
                'label' => (string)$t,
                'description' => (string)($r['Galaxy']['description'] ?? ''),
            );
        }
        $this->set('galaxyTypesAvailable', $galaxyTypes);
    }

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
