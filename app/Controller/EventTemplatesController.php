<?php
App::uses('AppController', 'Controller');
App::uses('EventTemplateDependencies', 'Tools');
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
