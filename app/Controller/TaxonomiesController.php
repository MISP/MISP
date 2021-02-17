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
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
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
        $this->paginate['recursive'] = -1;

        if (!empty($this->passedArgs['value'])) {
            $this->paginate['conditions']['id'] = $this->__search($this->passedArgs['value']);
        }

        if (isset($this->passedArgs['enabled'])) {
            $this->paginate['conditions']['enabled'] = $this->passedArgs['enabled'] ? 1 : 0;
        }

        if ($this->_isRest()) {
            $keepFields = array('conditions', 'contain', 'recursive', 'sort');
            $searchParams = array();
            foreach ($keepFields as $field) {
                if (!empty($this->paginate[$field])) {
                    $searchParams[$field] = $this->paginate[$field];
                }
            }
            $taxonomies = $this->Taxonomy->find('all', $searchParams);
        } else {
            $taxonomies = $this->paginate();
        }

        $taxonomies = $this->__tagCount($taxonomies);

        if ($this->_isRest()) {
            return $this->RestResponse->viewData($taxonomies, $this->response->type());
        }

        $this->set('taxonomies', $taxonomies);
        $this->set('passedArgsArray', $this->passedArgs);
    }

    public function view($id)
    {
        if (isset($this->passedArgs['pages'])) {
            $currentPage = $this->passedArgs['pages'];
        } else {
            $currentPage = 1;
        }
        $this->set('page', $currentPage);
        $urlparams = '';
        $passedArgs = array();
        App::uses('CustomPaginationTool', 'Tools');
        $filter = isset($this->passedArgs['filter']) ? $this->passedArgs['filter'] : false;
        $taxonomy = $this->Taxonomy->getTaxonomy($id, array('full' => true, 'filter' => $filter));
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
        $this->set('filter', $filter);
        $customPagination = new CustomPaginationTool();
        $params = $customPagination->createPaginationRules($taxonomy['entries'], $this->passedArgs, 'TaxonomyEntry');
        if ($params['sort'] == 'id') {
            $params['sort'] = 'tag';
        }
        $this->params->params['paging'] = array($this->modelClass => $params);
        $params = $customPagination->applyRulesOnArray($taxonomy['entries'], $params, 'taxonomies');
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($taxonomy, $this->response->type());
        } else {
            $this->set('entries', $taxonomy['entries']);
            $this->set('urlparams', $urlparams);
            $this->set('passedArgs', json_encode($passedArgs));
            $this->set('passedArgsArray', $passedArgs);
            $this->set('taxonomy', $taxonomy['Taxonomy']);
            $this->set('id', $id);
        }
    }

    public function enable($id)
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('Post')) {
            throw new MethodNotAllowedException(__('You don\'t have permission to do that.'));
        }
        $taxonomy = $this->Taxonomy->find('first', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.id' => $id),
        ));
        $taxonomy['Taxonomy']['enabled'] = true;
        $this->Taxonomy->save($taxonomy);
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->save(array(
                'org' => $this->Auth->user('Organisation')['name'],
                'model' => 'Taxonomy',
                'model_id' => $id,
                'email' => $this->Auth->user('email'),
                'action' => 'enable',
                'user_id' => $this->Auth->user('id'),
                'title' => 'Taxonomy enabled',
                'change' => $taxonomy['Taxonomy']['namespace'] . ' - enabled',
        ));
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Taxonomy', 'enable', $id, $this->response->type());
        } else {
            $this->Flash->success(__('Taxonomy enabled.'));
            $this->redirect($this->referer());
        }
    }

    public function disable($id)
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('Post')) {
            throw new MethodNotAllowedException(__('You don\'t have permission to do that.'));
        }
        $taxonomy = $this->Taxonomy->find('first', array(
                'recursive' => -1,
                'conditions' => array('Taxonomy.id' => $id),
        ));
        $this->Taxonomy->disableTags($id);
        $taxonomy['Taxonomy']['enabled'] = 0;
        $this->Taxonomy->save($taxonomy);
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->save(array(
                'org' => $this->Auth->user('Organisation')['name'],
                'model' => 'Taxonomy',
                'model_id' => $id,
                'email' => $this->Auth->user('email'),
                'action' => 'disable',
                'user_id' => $this->Auth->user('id'),
                'title' => 'Taxonomy disabled',
                'change' => $taxonomy['Taxonomy']['namespace'] . ' - disabled',
        ));
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Taxonomy', 'disable', $id, $this->response->type());
        } else {
            $this->Flash->success(__('Taxonomy disabled.'));
            $this->redirect($this->referer());
        }
    }

    public function import()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }
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
        $this->Log = ClassRegistry::init('Log');
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
                    $this->Log->create();
                    $this->Log->save(array(
                            'org' => $this->Auth->user('Organisation')['name'],
                            'model' => 'Taxonomy',
                            'model_id' => $id,
                            'email' => $this->Auth->user('email'),
                            'action' => 'update',
                            'user_id' => $this->Auth->user('id'),
                            'title' => 'Taxonomy updated',
                            'change' => $change,
                    ));
                    $successes++;
                }
            }
            if (isset($result['fails'])) {
                foreach ($result['fails'] as $id => $fail) {
                    $this->Log->create();
                    $this->Log->save(array(
                            'org' => $this->Auth->user('Organisation')['name'],
                            'model' => 'Taxonomy',
                            'model_id' => $id,
                            'email' => $this->Auth->user('email'),
                            'action' => 'update',
                            'user_id' => $this->Auth->user('id'),
                            'title' => 'Taxonomy failed to update',
                            'change' => $fail['namespace'] . ' could not be installed/updated. Error: ' . $fail['fail'],
                    ));
                    $fails++;
                }
            }
        } else {
            $this->Log->create();
            $this->Log->save(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => 'Taxonomy',
                    'model_id' => 0,
                    'email' => $this->Auth->user('email'),
                    'action' => 'update',
                    'user_id' => $this->Auth->user('id'),
                    'title' => 'Taxonomy update (nothing to update)',
                    'change' => 'Executed an update of the taxonomy library, but there was nothing to update.',
            ));
        }
        $message = '';
        if ($successes == 0 && $fails == 0) {
            $flashType = 'info';
            $message = __('All taxonomy libraries are up to date already.');
        } elseif ($successes == 0) {
            $flashType = 'error';
            $message = __('Could not update any of the taxonomy libraries');
        } else {
            $flashType = 'success';
            $message = __('Successfully updated ') . $successes . __(' taxonomy libraries.');
            if ($fails != 0) {
                $message .= __(' However, could not update ') . $fails . __(' taxonomy libraries.');
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Taxonomy', 'update', false, $this->response->type(), $message);
        } else {
            $this->Flash->{$flashType}($message);
            $this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
        }
    }

    public function addTag($taxonomy_id = false)
    {
        if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) || !$this->request->is('post')) {
            throw new NotFoundException(__('You don\'t have permission to do that.'));
        }
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

    public function hideTag($taxonomy_id = false)
    {
        if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) || !$this->request->is('post')) {
            throw new NotFoundException(__('You don\'t have permission to do that.'));
        }
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
        if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) || !$this->request->is('post')) {
            throw new NotFoundException(__('You don\'t have permission to do that.'));
        }
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
        if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) || !$this->request->is('post')) {
            throw new NotFoundException(__('You don\'t have permission to do that.'));
        }
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
        if ($this->request->is('post')) {
            $result = $this->Taxonomy->delete($id, true);
            if ($result) {
                $this->Flash->success(__('Taxonomy successfully deleted.'));
                $this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
            } else {
                $this->Flash->error(__('Taxonomy could not be deleted.'));
                $this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
            }
        } else {
            if ($this->request->is('ajax')) {
                $this->set('id', $id);
                $this->render('ajax/taxonomy_delete_confirmation');
            } else {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            }
        }
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
            $taxonomy['Taxonomy']['required'] = $this->request->data['Taxonomy']['required'];
            $result = $this->Taxonomy->save($taxonomy);
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'toggleRequired', $id, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleRequired', $id, $this->validationError, $this->response->type());
            }
        }

        $this->set('required', !$taxonomy['Taxonomy']['required']);
        $this->set('id', $id);
        $this->autoRender = false;
        $this->layout = 'ajax';
        $this->render('ajax/toggle_required');
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
}
