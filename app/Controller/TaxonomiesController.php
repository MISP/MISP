<?php
App::uses('AppController', 'Controller');

/**
 * @property Taxonomy $Taxonomy
 */
class TaxonomiesController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
        'contain' => array(
            'TaxonomyPredicate' => array(
                'fields' => array('TaxonomyPredicate.id', 'TaxonomyPredicate.value'),
                'TaxonomyEntry' => array('fields' => array('TaxonomyEntry.id', 'TaxonomyEntry.value'))
            )
        ),
        'order' => array(
                'Taxonomy.id' => 'DESC'
        ),
    );

    public function index()
    {
        $conditions = [];
        if (!empty($this->passedArgs['value'])) {
            $conditions['Taxonomy.id'] = $this->__search($this->passedArgs['value']);
        }

        $params = [
            'filters' => ['enabled', 'namespace', 'description'],
            'quickFilters' => ['namespace', 'description'],
            'conditions' => $conditions,
            'contain' => [
                'TaxonomyPredicate' => [
                    'fields' => ['TaxonomyPredicate.id', 'TaxonomyPredicate.value'],
                    'TaxonomyEntry' => ['fields' => ['TaxonomyEntry.id', 'TaxonomyEntry.value']]
                ]
            ],
            'afterFind' => function ($taxonomies) {
                return $this->__tagCount($taxonomies);
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('taxonomies', $this->viewVars['data']);
        $this->set('passedArgsArray', $this->passedArgs);
    }

    public function view($id)
    {
        $taxonomy = $this->Taxonomy->getTaxonomy($id, $this->_isRest());
        if (empty($taxonomy)) {
            throw new NotFoundException(__('Taxonomy not found.'));
        }

        if ($this->_isRest()) {
            return $this->RestResponse->viewData($taxonomy, $this->response->type());
        }

        $tagIds = array_column(array_column(array_column($taxonomy['entries'], 'existing_tag'), 'Tag'), 'id');
        $this->set('tag_count', count($taxonomy['entries']));

        $this->set('taxonomy', $taxonomy['Taxonomy']);
        $this->set('id', $taxonomy['Taxonomy']['id']);
    }

    public function taxonomy_tags($id)
    {
        $urlparams = '';
        App::uses('CustomPaginationTool', 'Tools');
        $filter = isset($this->passedArgs['filter']) ? $this->passedArgs['filter'] : false;
        $taxonomy = $this->Taxonomy->getTaxonomy($id, true, $filter);
        if (empty($taxonomy)) {
            throw new NotFoundException(__('Taxonomy not found.'));
        }
        $this->loadModel('EventTag');
        $this->loadModel('AttributeTag');

        $tagIds = array_column(array_column(array_column($taxonomy['entries'], 'existing_tag'), 'Tag'), 'id');
        $eventCount = $this->EventTag->countForTags($tagIds, $this->Auth->user());
        $attributeTags = $this->AttributeTag->countForTags($tagIds, $this->Auth->user());

        foreach ($taxonomy['entries'] as $key => $value) {
            $count = 0;
            $count_a = 0;
            if (!empty($value['existing_tag'])) {
                $tagId = $value['existing_tag']['Tag']['id'];
                $count = isset($eventCount[$tagId]) ? $eventCount[$tagId] : 0;
                $count_a = isset($attributeTags[$tagId]) ? $attributeTags[$tagId] : 0;
            }
            $taxonomy['entries'][$key]['events'] = $count;
            $taxonomy['entries'][$key]['attributes'] = $count_a;
        }
        $customPagination = new CustomPaginationTool();
        $params = $customPagination->createPaginationRules($taxonomy['entries'], $this->passedArgs, 'TaxonomyEntry');
        if ($params['sort'] == 'id') {
            $params['sort'] = 'tag';
        }
        $params['options'] = ['filter' => $filter];
        $this->params->params['paging'] = array($this->modelClass => $params);
        $params = $customPagination->applyRulesOnArray($taxonomy['entries'], $params, 'taxonomies');
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($taxonomy, $this->response->type());
        }

        if (isset($this->passedArgs['pages'])) {
            $currentPage = $this->passedArgs['pages'];
        } else {
            $currentPage = 1;
        }
        $this->set('page', $currentPage);

        $this->set('entries', $taxonomy['entries']);
        $this->set('urlparams', $urlparams);
        $this->set('passedArgs', json_encode($this->passedArgs));
        $this->set('passedArgsArray', $this->passedArgs);
        $this->set('taxonomy', $taxonomy['Taxonomy']);
        $this->set('id', $taxonomy['Taxonomy']['id']);
        $this->set('title_for_layout', __('%s Taxonomy Library', h(strtoupper($taxonomy['Taxonomy']['namespace']))));
        $this->layout = false;
        $this->render('ajax/taxonomy_tags');
    }

    public function export($id)
    {
        $taxonomy = $this->Taxonomy->find('first', [
            'recursive' => -1,
            'contain' => ['TaxonomyPredicate' => ['TaxonomyEntry']],
            'conditions' => is_numeric($id) ? ['Taxonomy.id' => $id] : ['LOWER(Taxonomy.namespace)' => mb_strtolower($id)],
        ]);
        if (empty($taxonomy)) {
            throw new NotFoundException(__('Taxonomy not found.'));
        }

        $data = [
            'namespace' => $taxonomy['Taxonomy']['namespace'],
            'description' => $taxonomy['Taxonomy']['description'],
            'version' => (int)$taxonomy['Taxonomy']['version'],
            'exclusive' => $taxonomy['Taxonomy']['exclusive'],
            'predicates' => [],
        ];

        foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
            $predicateOutput = [];
            foreach (['value', 'expanded', 'colour', 'description', 'exclusive', 'numerical_value'] as $field) {
                if (isset($predicate[$field]) && !empty($predicate[$field])) {
                    $predicateOutput[$field] = $predicate[$field];
                }
            }
            $data['predicates'][] = $predicateOutput;

            if (!empty($predicate['TaxonomyEntry'])) {
                $entries = [];
                foreach ($predicate['TaxonomyEntry'] as $entry) {
                    $entryOutput = [];
                    foreach(['value', 'expanded', 'colour', 'description', 'exclusive', 'numerical_value'] as $field) {
                        if (isset($entry[$field]) && !empty($entry[$field])) {
                            $entryOutput[$field] = $entry[$field];
                        }
                    }
                    $entries[] = $entryOutput;
                }
                $data['values'][] = [
                    'predicate' => $predicate['value'],
                    'entry' => $entries,
                ];
            }
        }

        return $this->RestResponse->viewData($data, 'json');
    }

    public function enable($id)
    {
        $this->request->allowMethod(['post']);

        $taxonomy = $this->Taxonomy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.id' => $id),
        ));
        if (empty($taxonomy)) {
            $message = __('Invalid taxonomy.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'enable', $id, $message);
            } else {
                $this->Flash->error($message);
                $this->redirect($this->referer());
            }
        } else {
            $taxonomy['Taxonomy']['enabled'] = true;
            $this->Taxonomy->save($taxonomy);

            $this->__log('enable', $id, 'Taxonomy enabled', $taxonomy['Taxonomy']['namespace'] . ' - enabled');

            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'enable', $id, $this->response->type());
            } else {
                $this->Flash->success(__('Taxonomy enabled.'));
                $this->redirect($this->referer());
            }
        }
    }

    public function disable($id)
    {
        $this->request->allowMethod(['post']);

        $taxonomy = $this->Taxonomy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.id' => $id),
        ));
        if (empty($taxonomy)) {
            $message = __('Invalid taxonomy.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'disable', $id, $message);
            } else {
                $this->Flash->error($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->Taxonomy->disableTags($id);
            $taxonomy['Taxonomy']['enabled'] = 0;
            $this->Taxonomy->save($taxonomy);

            $this->__log('disable', $id, 'Taxonomy disabled', $taxonomy['Taxonomy']['namespace'] . ' - disabled');

            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'disable', $id, $this->response->type());
            } else {
                $this->Flash->success(__('Taxonomy disabled.'));
                $this->redirect($this->referer());
            }
        }
    }

    public function toggleEnable($id)
    {
        $this->request->allowMethod(['post']);

        $taxonomy = $this->Taxonomy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.id' => $id)
        ));

        if (empty($taxonomy)) {
            $message = __('Invalid taxonomy.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleEnable', $id, $message);
            } else {
                $this->Flash->error($message);
                return $this->redirect($this->referer());
            }
        }

        $newState = !$taxonomy['Taxonomy']['enabled'];
        $taxonomy['Taxonomy']['enabled'] = $newState;

        if (!$newState) {
            $this->Taxonomy->disableTags($id);
        }

        $result = $this->Taxonomy->save($taxonomy);

        $action = $newState ? 'enable' : 'disable';
        $text = $newState ? 'enabled' : 'disabled';

        $this->__log(
            $action,
            $id,
            'Taxonomy ' . $text,
            $taxonomy['Taxonomy']['namespace'] . ' - ' . $text
        );

        if ($this->_isRest()) {
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'toggleEnable', $id, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleEnable', $id, __('Could not toggle state.'), $this->response->type());
            }
        } else {
            if ($result) {
                $this->Flash->success(__('Taxonomy %s.', $text));
            } else {
                $this->Flash->error(__('Something went wrong.'));
            }
            return $this->redirect($this->referer());
        }
    }

    public function import()
    {
        $this->request->allowMethod(['post']);

        try {
            $id = $this->Taxonomy->import($this->request->data);
            return $this->view($id);
        } catch (Exception $e) {
            return $this->RestResponse->saveFailResponse('Taxonomy', 'import', false, $e->getMessage());
        }
    }

    public function update()
    {
        $result = $this->Taxonomy->update();
        $fails = 0;
        $successes = 0;
        if (!empty($result)) {
            if (isset($result['success'])) {
                foreach ($result['success'] as $id => $success) {
                    if (isset($success['old'])) {
                        $change = $success['namespace'] . ': updated from v' . $success['old'] . ' to v' . $success['new'];
                    } else {
                        $change = $success['namespace'] . ' v' . $success['new'] . ' installed';
                    }
                    $this->__log('update', $id, 'Taxonomy updated', $change);
                    $successes++;
                }
            }
            if (isset($result['fails'])) {
                foreach ($result['fails'] as $id => $fail) {
                    $this->__log('update', $id, 'Taxonomy failed to update', $fail['namespace'] . ' could not be installed/updated. Error: ' . $fail['fail']);
                    $fails++;
                }
            }
        } else {
            $this->__log('update', 0, 'Taxonomy update (nothing to update)', 'Executed an update of the taxonomy library, but there was nothing to update.');
        }
        if ($successes == 0 && $fails == 0) {
            $flashType = 'info';
            $message = __('All taxonomy libraries are up to date already.');
        } elseif ($successes == 0) {
            $flashType = 'error';
            $message = __('Could not update any of the taxonomy libraries');
        } else {
            $flashType = 'success';
            $message = __('Successfully updated %s taxonomy libraries.', $successes);
            if ($fails != 0) {
                $message .= __(' However, could not update %s taxonomy libraries.', $fails);
            }
        }
        if ($this->_isRest()) {
            if ($flashType === 'error') {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'update', false, $message, $this->response->type());
            }
            return $this->RestResponse->saveSuccessResponse('Taxonomy', 'update', false, $this->response->type(), $message);
        } else {
            $this->Flash->{$flashType}($message);
            $this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
        }
    }

    public function addTag($taxonomy_id = false)
    {
        if ($this->theme === 'Overmind') {
            $this->layout=false;
        }
        if ($this->request->is('get')) {
            if (empty($taxonomy_id) && !empty($this->request->params['named']['taxonomy_id'])) {
                $taxonomy_id = $this->request->params['named']['taxonomy_id'];
            }
            if (
                empty($taxonomy_id) ||
                empty($this->request->params['named']['name'])
            ) {
                throw new MethodNotAllowedException(__('Taxonomy ID or tag name must be provided.'));
            } else {
                $this->request->data['Taxonomy']['taxonomy_id'] = $taxonomy_id;
                $this->request->data['Taxonomy']['name'] = $this->request->params['named']['name'];
            }
        } else {
            if ($taxonomy_id) {
                $result = $this->Taxonomy->addTags($taxonomy_id);
            } else {
                if (isset($this->request->data['Taxonomy'])) {
                    $this->request->data['Tag'] = $this->request->data['Taxonomy'];
                    unset($this->request->data['Taxonomy']);
                }
                if (isset($this->request->data['Tag']['request'])) {
                    $this->request->data['Tag'] = $this->request->data['Tag']['request'];
                }
                if (!isset($this->request->data['Tag']['nameList'])) {
                    $this->request->data['Tag']['nameList'] = array($this->request->data['Tag']['name']);
                } else {
                    $this->request->data['Tag']['nameList'] = json_decode($this->request->data['Tag']['nameList'], true);
                }
                $result = $this->Taxonomy->addTags($this->request->data['Tag']['taxonomy_id'], $this->request->data['Tag']['nameList']);
            }
            if ($result) {
                $message = __('The tag(s) has been saved.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Taxonomy', 'addTag', $taxonomy_id, $this->response->type(), $message);
                }
                $this->Flash->success($message);
            } else {
                $message = __('The tag(s) could not be saved. Please, try again.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Taxonomy', 'addTag', $taxonomy_id, $message, $this->response->type());
                }
                $this->Flash->error($message);
            }
            $this->redirect($this->referer());
        }
    }

    public function hideTag($taxonomy_id = false)
    {
        $this->request->allowMethod(['post']);

        if ($taxonomy_id) {
            $result = $this->Taxonomy->hideTags($taxonomy_id);
        } else {
            if (isset($this->request->data['Taxonomy'])) {
                $this->request->data['Tag'] = $this->request->data['Taxonomy'];
                unset($this->request->data['Taxonomy']);
            }
            if (isset($this->request->data['Tag']['request'])) {
                $this->request->data['Tag'] = $this->request->data['Tag']['request'];
            }
            if (!isset($this->request->data['Tag']['nameList'])) {
                $this->request->data['Tag']['nameList'] = array($this->request->data['Tag']['name']);
            } else {
                $this->request->data['Tag']['nameList'] = json_decode($this->request->data['Tag']['nameList'], true);
            }
            $result = $this->Taxonomy->hideTags($this->request->data['Tag']['taxonomy_id'], $this->request->data['Tag']['nameList']);
        }
        if ($result) {
            $this->Flash->success(__('The tag(s) has been saved.'));
        } else {
            $this->Flash->error(__('The tag(s) could not be saved. Please, try again.'));
        }
        $this->redirect($this->referer());
    }

    public function unhideTag($taxonomy_id = false)
    {
        $this->request->allowMethod(['post']);

        if ($taxonomy_id) {
            $result = $this->Taxonomy->unhideTags($taxonomy_id);
        } else {
            if (isset($this->request->data['Taxonomy'])) {
                $this->request->data['Tag'] = $this->request->data['Taxonomy'];
                unset($this->request->data['Taxonomy']);
            }
            if (isset($this->request->data['Tag']['request'])) {
                $this->request->data['Tag'] = $this->request->data['Tag']['request'];
            }
            if (!isset($this->request->data['Tag']['nameList'])) {
                $this->request->data['Tag']['nameList'] = array($this->request->data['Tag']['name']);
            } else {
                $this->request->data['Tag']['nameList'] = json_decode($this->request->data['Tag']['nameList'], true);
            }
            $result = $this->Taxonomy->unhideTags($this->request->data['Tag']['taxonomy_id'], $this->request->data['Tag']['nameList']);
        }
        if ($result) {
            $this->Flash->success(__('The tag(s) has been saved.'));
        } else {
            $this->Flash->error(__('The tag(s) could not be saved. Please, try again.'));
        }
        $this->redirect($this->referer());
    }

    public function disableTag($taxonomy_id = false)
    {
        if ($this->theme === 'Overmind') {
            $this->layout=false;
        }
        if ($this->request->is('get')) {
            if (empty($taxonomy_id) && !empty($this->request->params['named']['taxonomy_id'])) {
                $taxonomy_id = $this->request->params['named']['taxonomy_id'];
            }
            if (
                empty($taxonomy_id) ||
                empty($this->request->params['named']['name'])
            ) {
                throw new MethodNotAllowedException(__('Taxonomy ID or tag name must be provided.'));
            } else {
                $this->request->data['Taxonomy']['taxonomy_id'] = $taxonomy_id;
                $this->request->data['Taxonomy']['name'] = $this->request->params['named']['name'];
            }
        } else {
            if ($taxonomy_id) {
                $result = $this->Taxonomy->disableTags($taxonomy_id);
            } else {
                if (isset($this->request->data['Taxonomy'])) {
                    $this->request->data['Tag'] = $this->request->data['Taxonomy'];
                    unset($this->request->data['Taxonomy']);
                }
                if (isset($this->request->data['Tag']['request'])) {
                    $this->request->data['Tag'] = $this->request->data['Tag']['request'];
                }
                if (!isset($this->request->data['Tag']['nameList'])) {
                    $this->request->data['Tag']['nameList'] = array($this->request->data['Tag']['name']);
                } else {
                    $this->request->data['Tag']['nameList'] = json_decode($this->request->data['Tag']['nameList'], true);
                }
                $result = $this->Taxonomy->disableTags($this->request->data['Tag']['taxonomy_id'], $this->request->data['Tag']['nameList']);
            }
            if ($result) {
                $this->Flash->success(__('The tag(s) has been hidden.'));
            } else {
                $this->Flash->error(__('The tag(s) could not be hidden. Please, try again.'));
            }
            $this->redirect($this->referer());
        }
    }

    public function taxonomyMassConfirmation($id)
    {
        $this->set('id', $id);
        $this->render('ajax/taxonomy_mass_confirmation');
    }

    public function taxonomyMassHide($id)
    {
        $this->set('id', $id);
        $this->render('ajax/taxonomy_mass_hide');
    }

    public function taxonomyMassUnhide($id)
    {
        $this->set('id', $id);
        $this->render('ajax/taxonomy_mass_unhide');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'Taxonomy',
            'restName' => 'Taxonomies',
            'itemName' => 'Taxonomy',
            'view' => 'ajax/taxonomyDeleteConfirmationForm',
            'checkModifyCallback' => function() {
                return $this->userRole['perm_site_admin'];
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s taxonomy deleted.', '%s taxonomies deleted.', $count, $count);
            }
        ]);
    }

    public function toggleRequired($id)
    {
        $taxonomy = $this->Taxonomy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.id' => $id)
        ));
        if (empty($taxonomy)) {
            return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleRequired', $id, 'Invalid Taxonomy', $this->response->type());
        }
        if ($this->request->is('post')) {
            if ($this->theme !== 'Overmind') {
                $taxonomy['Taxonomy']['required'] = $this->request->data['Taxonomy']['required'];
            } else {
                $taxonomy['Taxonomy']['required'] = !$taxonomy['Taxonomy']['required'];
            }
            $result = $this->Taxonomy->save($taxonomy);
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Taxonomy', 'toggleRequired', $id, $this->response->type());
                } else {
                    return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleRequired', $id, $this->validationError, $this->response->type());
                }
            } else {
                if ($result) {
                    $this->Flash->success(__('Required field switched.'));
                    $this->redirect($this->referer());
                } else {
                    $this->Flash->error(__('Something went wrong.'));
                    $this->redirect($this->referer());
                }
            }
        }

        if ($this->theme !== 'Overmind') {
            $this->set('required', !$taxonomy['Taxonomy']['required']);
            $this->set('id', $id);
            $this->autoRender = false;
            $this->layout = false;
            $this->render('ajax/toggle_required');
        }
    }

    public function toggleHighlighted($id)
    {
        $taxonomy = $this->Taxonomy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.id' => $id)
        ));
        if (empty($taxonomy)) {
            return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleHighlighted', $id, 'Invalid Taxonomy', $this->response->type());
        }
        if ($this->request->is('post')) {
            if ($this->theme !== 'Overmind') {
                $taxonomy['Taxonomy']['highlighted'] = $this->request->data['Taxonomy']['highlighted'];
            } else {
                $taxonomy['Taxonomy']['highlighted'] = !$taxonomy['Taxonomy']['highlighted'];
            }
            $result = $this->Taxonomy->save($taxonomy);
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('Taxonomy', 'toggleHighlighted', $id, $this->response->type());
                } else {
                    return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleHighlighted', $id, $this->validationError, $this->response->type());
                }
            } else {
                if ($result) {
                    $this->Flash->success(__('Highlighted field switched.'));
                    $this->redirect($this->referer());
                } else {
                    $this->Flash->error(__('Something went wrong.'));
                    $this->redirect($this->referer());
                }
            }
        }

        if ($this->theme !== 'Overmind') {
            $this->set('highlighted', !$taxonomy['Taxonomy']['highlighted']);
            $this->set('id', $id);
            $this->autoRender = false;
            $this->layout = false;
            $this->render('ajax/toggle_highlighted');
        }
    }

    /**
     * @param string $action
     * @param int $modelId
     * @param string $title
     * @param string $change
     * @return void
     * @throws Exception
     */
    private function __log($action, $modelId, $title, $change)
    {
        /** @var Log $log */
        $log = ClassRegistry::init('Log');
        $log->createLogEntry($this->Auth->user(), $action, 'Taxonomy', $modelId, $title, $change);
    }

    /**
     * Attach tag counts.
     * @param array $taxonomies
     * @return array
     */
    private function __tagCount(array $taxonomies)
    {
        $tags = [];
        foreach ($taxonomies as $taxonomyPos => $taxonomy) {
            $total = 0;
            foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
                if (isset($predicate['TaxonomyEntry']) && !empty($predicate['TaxonomyEntry'])) {
                    foreach ($predicate['TaxonomyEntry'] as $entry) {
                        $tag = mb_strtolower($taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value'] . '="' . $entry['value'] . '"');
                        $tags[$tag] = $taxonomyPos;
                        $total++;
                    }
                } else {
                    $tag = mb_strtolower($taxonomy['Taxonomy']['namespace'] . ':' . $predicate['value']);
                    $tags[$tag] = $taxonomyPos;
                    $total++;
                }
            }
            $taxonomies[$taxonomyPos]['total_count'] = $total;
            $taxonomies[$taxonomyPos]['current_count'] = 0;
            unset($taxonomies[$taxonomyPos]['TaxonomyPredicate']);
        }

        $this->loadModel('Tag');
        $existingTags = $this->Tag->find('column', [
            'fields' => ['Tag.name'],
            'conditions' => [
                'lower(Tag.name)' => array_keys($tags),
                'hide_tag' => 0
            ],
        ]);

        foreach ($existingTags as $existingTag) {
            $existingTag = mb_strtolower($existingTag);
            if (isset($tags[$existingTag])) {
                $taxonomies[$tags[$existingTag]]['current_count']++;
            }
        }

        return $taxonomies;
    }

    private function __search($value)
    {
        $value = mb_strtolower(trim($value));
        $searchTerm = "%$value%";
        $taxonomyPredicateIds = $this->Taxonomy->TaxonomyPredicate->TaxonomyEntry->find('column', [
            'fields' => ['TaxonomyEntry.taxonomy_predicate_id'],
            'conditions' => ['OR' => [
                'LOWER(value) LIKE' => $searchTerm,
                'LOWER(expanded) LIKE' => $searchTerm,
            ]],
            'unique' => true,
        ]);

        $taxonomyIds = $this->Taxonomy->TaxonomyPredicate->find('column', [
            'fields' => ['TaxonomyPredicate.taxonomy_id'],
            'conditions' => ['OR' => [
                'id' => $taxonomyPredicateIds,
                'LOWER(value) LIKE' => $searchTerm,
                'LOWER(expanded) LIKE' => $searchTerm,
            ]],
            'unique' => true,
        ]);

        $taxonomyIds = $this->Taxonomy->find('column', [
            'fields' => ['Taxonomy.id'],
            'conditions' => ['OR' => [
                'id' => $taxonomyIds,
                'LOWER(namespace) LIKE' => $searchTerm,
                'LOWER(description) LIKE' => $searchTerm,
            ]],
        ]);

        return $taxonomyIds;
    }


    public function normalizeCustomTagsToTaxonomyFormat()
    {
        $this->request->allowMethod(['post', 'put']);
        $conversionResult = $this->Taxonomy->normalizeCustomTagsToTaxonomyFormat();
        $this->Flash->success(__('%s tags successfully converted. %s row updated.', $conversionResult['tag_converted'], $conversionResult['row_updated']));
        $this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
    }


    // --- ENABLED ---
    public function massEnable($idList = null)
    {
        return $this->_massToggleState($idList, 1, 'enabled');
    }

    public function massDisable($idList = null)
    {
        return $this->_massToggleState($idList, 0, 'enabled');
    }

    // --- REQUIRED ---
    public function massRequire($idList = null)
    {
        return $this->_massToggleState($idList, 1, 'required');
    }

    public function massOptional($idList = null)
    {
        return $this->_massToggleState($idList, 0, 'required');
    }

    // --- HIGHLIGHTED ---
    public function massHighlight($idList = null)
    {
        return $this->_massToggleState($idList, 1, 'highlighted');
    }

    public function massRemoveHighlight($idList = null)
    {
        return $this->_massToggleState($idList, 0, 'highlighted');
    }

    private function _massToggleState($idList = null, $state = null, $field = '')
    {
        $cleanIdList = htmlspecialchars_decode(urldecode($idList));
        $ids = json_decode($cleanIdList, true);

        if (empty($ids) || !is_array($ids)) {
            $message = __('Invalid IDs provided.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Taxonomies', 'massToggle', false, $message, $this->response->type());
            }
            return new CakeResponse([
                'body' => json_encode(['saved' => false, 'errors' => $message]),
                'status' => 200,
                'type' => 'json'
            ]);
        }

        if (!in_array($field, ['enabled', 'required', 'highlighted'])) {
            $message = __('Invalid field provided.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Taxonomies', 'massToggle', false, $message, $this->response->type());
            }
            return new CakeResponse([
                'body' => json_encode(['saved' => false, 'errors' => $message]),
                'status' => 200,
                'type' => 'json'
            ]);
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            $successCount = 0;

            foreach ($ids as $id) {
                $this->Taxonomy->id = $id;

                if ($this->Taxonomy->exists()) {
                    if ($this->Taxonomy->saveField($field, $state)) {

                        if ($field === 'enabled' && !$state) {
                            $this->Taxonomy->disableTags($id);
                        }
                        // Log
                        // $action = $state ? 'enable' : 'disable';
                        // if ($field === 'required') {
                        //     $action = $state ? 'required' : 'required';
                        // } elseif ($field === 'highlighted') {
                        //     $action = $state ? 'highlighted' : 'highlighted';
                        // }

                        // $this->__log(
                        //     $action,
                        //     $id,
                        //     'Taxonomy ' . $field . ' changed',
                        //     'Taxonomy ID ' . $id . ' set ' . $field . ' = ' . $state
                        // );

                        $successCount++;
                    }
                }
            }

            $actionTextMap = [
                'enabled' => $state ? __('enabled') : __('disabled'),
                'required' => $state ? __('required') : __('optional'),
                'highlighted' => $state ? __('highlighted') : __('not highlighted'),
            ];

            $message = __('%s Taxonomies successfully %s.', $successCount, $actionTextMap[$field]);

            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Taxonomies', 'massToggle', false, $this->response->type(), $message);
            }
            if ($this->request->is('ajax')) {
                return new CakeResponse([
                    'body' => json_encode(['saved' => true, 'success' => $message]),
                    'status' => 200,
                    'type' => 'json'
                ]);
            }

            $this->Flash->success($message);
            return $this->redirect($this->referer(['action' => 'index']));
        }

        $this->layout = false;

        $actionTextMap = [
            'enabled' => $state ? 'enable' : 'disable',
            'required' => $state ? 'require' : 'make optional',
            'highlighted' => $state ? 'highlight' : 'remove highlight on',
        ];

        $urlMap = [
            'enabled' => $state ? 'massEnable' : 'massDisable',
            'required' => $state ? 'massRequire' : 'massOptional',
            'highlighted' => $state ? 'massHighlight' : 'massRemovehighlight',
        ];

        $this->set('actionText', __($actionTextMap[$field]));
        $this->set('idArray', $ids);
        $this->set('state', $state);
        $this->set('url', '/taxonomies/' . $urlMap[$field] . '/' . urlencode($cleanIdList));

        $this->render('ajax/taxonomyToggleConfirmationForm');
    }

}
