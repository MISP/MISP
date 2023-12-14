<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Lib\Tools\CustomPaginationTool;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\ORM\Locator\LocatorAwareTrait;
use Exception;

class TaxonomiesController extends AppController
{
    use LocatorAwareTrait;

    public $paginate = [
        'limit' => 60,
        'contain' => [
            'TaxonomyPredicates' => [
                'fields' => ['TaxonomyPredicates.id', 'TaxonomyPredicates.taxonomy_id', 'TaxonomyPredicates.value'],
                'TaxonomyEntries' => ['fields' => ['TaxonomyEntries.id', 'TaxonomyEntries.taxonomy_predicate_id', 'TaxonomyEntries.value']]
            ]
        ],
        'order' => [
            'Taxonomies.id' => 'DESC'
        ],
    ];

    public function index()
    {
        $this->paginate['recursive'] = -1;

        if (!empty($this->request->getQueryParams()['value'])) {
            $this->paginate['conditions']['id'] = $this->__search($this->request->getQueryParams()['value']);
        }

        if (isset($this->request->getQueryParams()['enabled'])) {
            $this->paginate['conditions']['enabled'] = $this->request->getQueryParams()['enabled'] ? 1 : 0;
        }

        if ($this->ParamHandler->isRest()) {
            $keepFields = ['conditions', 'contain', 'recursive', 'sort'];
            $searchParams = [];
            foreach ($keepFields as $field) {
                if (!empty($this->paginate[$field])) {
                    $searchParams[$field] = $this->paginate[$field];
                }
            }
            $taxonomies = $this->Taxonomies->find('all', $searchParams);
        } else {
            $taxonomies = $this->paginate();
        }

        $taxonomies = $this->__tagCount($taxonomies->toArray());

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($taxonomies, $this->response->getType());
        }

        $this->set('taxonomies', $taxonomies);
        $this->set('passedArgsArray', $this->request->getQueryParams());
    }

    public function view($id)
    {
        $taxonomy = $this->Taxonomies->getTaxonomy($id, $this->ParamHandler->isRest());
        if (empty($taxonomy)) {
            throw new NotFoundException(__('Taxonomy not found.'));
        }

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($taxonomy, $this->response->getType());
        }

        $this->set('taxonomy', $taxonomy['Taxonomy']);
        $this->set('id', $taxonomy['Taxonomy']['id']);
    }

    public function taxonomyTags($id)
    {
        $urlparams = '';
        $filter = isset($this->request->getQueryParams()['filter']) ? $this->request->getQueryParams()['filter'] : false;
        $taxonomy = $this->Taxonomies->getTaxonomy($id, true, $filter);
        if (empty($taxonomy)) {
            throw new NotFoundException(__('Taxonomy not found.'));
        }

        $EventTagsTable = $this->fetchTable('EventTags');
        $AttributeTagsTable = $this->fetchTable('AttributeTags');

        $tagIds = array_column(array_column(array_column($taxonomy['entries'], 'existing_tag'), 'Tag'), 'id');
        $eventCount = $EventTagsTable->countForTags($tagIds, $this->ACL->getUser()->toArray());
        $attributeTags = $AttributeTagsTable->countForTags($tagIds, $this->ACL->getUser()->toArray());

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
        $params = $customPagination->createPaginationRules($taxonomy['entries'], $this->request->getQueryParams(), 'TaxonomyEntry');
        if ($params['sort'] == 'id') {
            $params['sort'] = 'tag';
        }
        $params['options'] = ['filter' => $filter];
        $this->paginate = ['Taxonomies' => $params];
        $params = $customPagination->applyRulesOnArray($taxonomy['entries'], $params, 'taxonomies');
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($taxonomy, $this->response->getType());
        }

        if (isset($this->request->getQueryParams()['pages'])) {
            $currentPage = $this->request->getQueryParams()['pages'];
        } else {
            $currentPage = 1;
        }
        $this->set('page', $currentPage);

        $this->set('entries', $taxonomy['entries']);
        $this->set('urlparams', $urlparams);
        $this->set('passedArgs', json_encode($this->request->getQueryParams()));
        $this->set('passedArgsArray', $this->request->getQueryParams());
        $this->set('taxonomy', $taxonomy['Taxonomy']);
        $this->set('id', $taxonomy['Taxonomy']['id']);
        $this->set('title_for_layout', __('%s Taxonomy Library', h(strtoupper($taxonomy['Taxonomy']['namespace']))));
        $this->render('ajax/taxonomy_tags');
    }

    public function export($id)
    {
        $taxonomy = $this->Taxonomies->find(
            'all',
            [
                'recursive' => -1,
                'contain' => ['TaxonomyPredicates' => ['TaxonomyEntries']],
                'conditions' => is_numeric($id) ? ['id' => $id] : ['LOWER(namespace)' => mb_strtolower($id)],
            ]
        )->first();
        if (empty($taxonomy)) {
            throw new NotFoundException(__('Taxonomy not found.'));
        }

        $data = [
            'namespace' => $taxonomy['namespace'],
            'description' => $taxonomy['description'],
            'version' => (int)$taxonomy['version'],
            'exclusive' => $taxonomy['exclusive'],
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
                    foreach (['value', 'expanded', 'colour', 'description', 'exclusive', 'numerical_value'] as $field) {
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

        $taxonomy = $this->Taxonomies->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['Taxonomy.id' => $id],
            ]
        )->first();
        if (empty($taxonomy)) {
            $message = __('Invalid taxonomy.');
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'enable', $id, $message);
            } else {
                $this->Flash->error($message);
                $this->redirect($this->referer());
            }
        } else {
            $taxonomy['Taxonomy']['enabled'] = true;
            $this->Taxonomies->save($taxonomy);

            $this->__log('enable', $id, 'Taxonomy enabled', $taxonomy['Taxonomy']['namespace'] . ' - enabled');

            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'enable', $id, $this->response->getType());
            } else {
                $this->Flash->success(__('Taxonomy enabled.'));
                $this->redirect($this->referer());
            }
        }
    }

    public function disable($id)
    {
        $this->request->allowMethod(['post']);

        $taxonomy = $this->Taxonomies->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['Taxonomy.id' => $id],
            ]
        )->first();
        if (empty($taxonomy)) {
            $message = __('Invalid taxonomy.');
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'disable', $id, $message);
            } else {
                $this->Flash->error($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->Taxonomies->disableTags($id);
            $taxonomy['Taxonomy']['enabled'] = 0;
            $this->Taxonomies->save($taxonomy);

            $this->__log('disable', $id, 'Taxonomy disabled', $taxonomy['Taxonomy']['namespace'] . ' - disabled');

            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'disable', $id, $this->response->getType());
            } else {
                $this->Flash->success(__('Taxonomy disabled.'));
                $this->redirect($this->referer());
            }
        }
    }

    public function import()
    {
        $this->request->allowMethod(['post']);

        try {
            $id = $this->Taxonomies->import($this->request->getData());
            return $this->view($id);
        } catch (Exception $e) {
            return $this->RestResponse->saveFailResponse('Taxonomy', 'import', false, $e->getMessage());
        }
    }

    public function update()
    {
        $result = $this->Taxonomies->update();
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
            $message = __('Successfully updated {0} taxonomy libraries.', $successes);
            if ($fails != 0) {
                $message .= __(' However, could not update %s taxonomy libraries.', $fails);
            }
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Taxonomy', 'update', false, $this->response->getType(), $message);
        } else {
            $this->Flash->{$flashType}($message);
            $this->redirect(['controller' => 'taxonomies', 'action' => 'index']);
        }
    }

    public function addTag($taxonomy_id = false)
    {
        $data = $this->request->getData();
        if ($this->request->is('get')) {
            if (empty($taxonomy_id) && !empty($this->request->getParam('named')['taxonomy_id'])) {
                $taxonomy_id = $this->request->getParam('named')['taxonomy_id'];
            }
            if (
                empty($taxonomy_id) ||
                empty($this->request->getParam('named')['name'])
            ) {
                throw new MethodNotAllowedException(__('Taxonomy ID or tag name must be provided.'));
            } else {
                $data['Taxonomy']['taxonomy_id'] = $taxonomy_id;
                $data['Taxonomy']['name'] = $this->request->getParam('named')['name'];
            }
        } else {
            if ($taxonomy_id) {
                $result = $this->Taxonomies->addTags($taxonomy_id);
            } else {
                if (isset($data['Taxonomy'])) {
                    $data['Tag'] = $data['Taxonomy'];
                    unset($data['Taxonomy']);
                }
                if (isset($data['Tag']['request'])) {
                    $data['Tag'] = $data['Tag']['request'];
                }
                if (!isset($data['Tag']['nameList'])) {
                    $data['Tag']['nameList'] = [$data['Tag']['name']];
                } else {
                    $data['Tag']['nameList'] = json_decode($data['Tag']['nameList'], true);
                }
                $result = $this->Taxonomies->addTags($data['Tag']['taxonomy_id'], $data['Tag']['nameList']);
            }
            if ($result) {
                $message = __('The tag(s) has been saved.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Taxonomy', 'addTag', $taxonomy_id, $this->response->getType(), $message);
                }
                $this->Flash->success($message);
            } else {
                $message = __('The tag(s) could not be saved. Please, try again.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Taxonomy', 'addTag', $taxonomy_id, $message, $this->response->getType());
                }
                $this->Flash->error($message);
            }
            $this->redirect($this->referer());
        }
    }

    public function hideTag($taxonomy_id = false)
    {
        $this->request->allowMethod(['post']);
        $data = $this->request->getData();

        if ($taxonomy_id) {
            $result = $this->Taxonomies->hideTags($taxonomy_id);
        } else {
            if (isset($data['Taxonomy'])) {
                $data['Tag'] = $data['Taxonomy'];
                unset($data['Taxonomy']);
            }
            if (isset($data['Tag']['request'])) {
                $data['Tag'] = $data['Tag']['request'];
            }
            if (!isset($data['Tag']['nameList'])) {
                $data['Tag']['nameList'] = [$data['Tag']['name']];
            } else {
                $data['Tag']['nameList'] = json_decode($data['Tag']['nameList'], true);
            }
            $result = $this->Taxonomies->hideTags($data['Tag']['taxonomy_id'], $data['Tag']['nameList']);
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
        $data = $this->request->getData();

        if ($taxonomy_id) {
            $result = $this->Taxonomies->unhideTags($taxonomy_id);
        } else {
            if (isset($data['Taxonomy'])) {
                $data['Tag'] = $data['Taxonomy'];
                unset($data['Taxonomy']);
            }
            if (isset($data['Tag']['request'])) {
                $data['Tag'] = $data['Tag']['request'];
            }
            if (!isset($data['Tag']['nameList'])) {
                $data['Tag']['nameList'] = [$data['Tag']['name']];
            } else {
                $data['Tag']['nameList'] = json_decode($data['Tag']['nameList'], true);
            }
            $result = $this->Taxonomies->unhideTags($data['Tag']['taxonomy_id'], $data['Tag']['nameList']);
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
        $data = $this->request->getData();

        if ($this->request->is('get')) {
            if (empty($taxonomy_id) && !empty($this->request->getParam('named')['taxonomy_id'])) {
                $taxonomy_id = $this->request->getParam('named')['taxonomy_id'];
            }
            if (
                empty($taxonomy_id) ||
                empty($this->request->getParam('named')['name'])
            ) {
                throw new MethodNotAllowedException(__('Taxonomy ID or tag name must be provided.'));
            } else {
                $data['Taxonomy']['taxonomy_id'] = $taxonomy_id;
                $data['Taxonomy']['name'] = $this->request->getParam('named')['name'];
            }
        } else {
            if ($taxonomy_id) {
                $result = $this->Taxonomies->disableTags($taxonomy_id);
            } else {
                if (isset($data['Taxonomy'])) {
                    $data['Tag'] = $data['Taxonomy'];
                    unset($data['Taxonomy']);
                }
                if (isset($data['Tag']['request'])) {
                    $data['Tag'] = $data['Tag']['request'];
                }
                if (!isset($data['Tag']['nameList'])) {
                    $data['Tag']['nameList'] = [$data['Tag']['name']];
                } else {
                    $data['Tag']['nameList'] = json_decode($data['Tag']['nameList'], true);
                }
                $result = $this->Taxonomies->disableTags($data['Tag']['taxonomy_id'], $data['Tag']['nameList']);
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
        if ($this->request->is('post')) {
            $result = $this->Taxonomies->delete($id, true);
            if ($result) {
                $this->Flash->success(__('Taxonomy successfully deleted.'));
                $this->redirect(['controller' => 'taxonomies', 'action' => 'index']);
            } else {
                $this->Flash->error(__('Taxonomy could not be deleted.'));
                $this->redirect(['controller' => 'taxonomies', 'action' => 'index']);
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
        $taxonomy = $this->Taxonomies->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['Taxonomy.id' => $id]
            ]
        )->first();
        if (empty($taxonomy)) {
            return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleRequired', $id, 'Invalid Taxonomy', $this->response->getType());
        }
        if ($this->request->is('post')) {
            $taxonomy['Taxonomy']['required'] = $this->request->gtData()['Taxonomy']['required'];
            $result = $this->Taxonomies->save($taxonomy);
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'toggleRequired', $id, $this->response->getType());
            } else {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleRequired', $id, $this->validationError, $this->response->getType());
            }
        }

        $this->set('required', !$taxonomy['Taxonomy']['required']);
        $this->set('id', $id);
        $this->autoRender = false;
        $this->layout = false;
        $this->render('ajax/toggle_required');
    }

    public function toggleHighlighted($id)
    {
        $taxonomy = $this->Taxonomies->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['Taxonomy.id' => $id]
            ]
        )->first();
        if (empty($taxonomy)) {
            return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleHighlighted', $id, 'Invalid Taxonomy', $this->response->getType());
        }
        if ($this->request->is('post')) {
            $taxonomy['Taxonomy']['highlighted'] = $this->request->getData()['Taxonomy']['highlighted'];
            $result = $this->Taxonomies->save($taxonomy);
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('Taxonomy', 'toggleHighlighted', $id, $this->response->getType());
            } else {
                return $this->RestResponse->saveFailResponse('Taxonomy', 'toggleHighlighted', $id, $this->validationError, $this->response->getType());
            }
        }

        $this->set('highlighted', !$taxonomy['Taxonomy']['highlighted']);
        $this->set('id', $id);
        $this->autoRender = false;
        $this->layout = false;
        $this->render('ajax/toggle_highlighted');
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
        /** @var LogsTable $LogsTable */
        $LogsTable = $this->fetchTable('Logs');
        $LogsTable->createLogEntry($this->ACL->getUser()->toArray(), $action, 'Taxonomy', $modelId, $title, $change);
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
                        $tag = mb_strtolower($taxonomy['namespace'] . ':' . $predicate['value'] . '="' . $entry['value'] . '"');
                        $tags[$tag] = $taxonomyPos;
                        $total++;
                    }
                } else {
                    $tag = mb_strtolower($taxonomy['namespace'] . ':' . $predicate['value']);
                    $tags[$tag] = $taxonomyPos;
                    $total++;
                }
            }
            $taxonomies[$taxonomyPos]['total_count'] = $total;
            $taxonomies[$taxonomyPos]['current_count'] = 0;
            unset($taxonomies[$taxonomyPos]['TaxonomyPredicate']);
        }

        $TagsTable = $this->fetchTable('Tags');
        if (!empty($tags)) {
            $existingTags = $TagsTable->find(
                'column',
                [
                    'fields' => ['Tags.name'],
                    'conditions' => [
                        'lower(name) IN' => array_keys($tags),
                        'hide_tag' => 0
                    ],
                ]
            );
        } else {
            $existingTags = $TagsTable->find('column', ['fields' => ['name']]);
        }

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
        $taxonomyPredicateIds = $this->Taxonomies->TaxonomyPredicates->TaxonomyEntry->find(
            'column',
            [
                'fields' => ['TaxonomyEntry.taxonomy_predicate_id'],
                'conditions' => [
                    'OR' => [
                        'LOWER(value) LIKE' => $searchTerm,
                        'LOWER(expanded) LIKE' => $searchTerm,
                    ]

                ],
                'unique' => true,
            ]
        );

        $taxonomyIds = $this->Taxonomies->TaxonomyPredicates->find(
            'column',
            [
                'fields' => ['TaxonomyPredicate.taxonomy_id'],
                'conditions' => [
                    'OR' => [
                        'id' => $taxonomyPredicateIds,
                        'LOWER(value) LIKE' => $searchTerm,
                        'LOWER(expanded) LIKE' => $searchTerm,
                    ]

                ],
                'unique' => true,
            ]
        );

        $taxonomyIds = $this->Taxonomies->find(
            'column',
            [
                'fields' => ['Taxonomy.id'],
                'conditions' => [
                    'OR' => [
                        'id' => $taxonomyIds,
                        'LOWER(namespace) LIKE' => $searchTerm,
                        'LOWER(description) LIKE' => $searchTerm,
                    ]

                ],
            ]
        );

        return $taxonomyIds;
    }


    public function normalizeCustomTagsToTaxonomyFormat()
    {
        $this->request->allowMethod(['post', 'put']);
        $conversionResult = $this->Taxonomies->normalizeCustomTagsToTaxonomyFormat();
        $this->Flash->success(__('%s tags successfully converted. %s row updated.', $conversionResult['tag_converted'], $conversionResult['row_updated']));
        $this->redirect(['controller' => 'taxonomies', 'action' => 'index']);
    }
}
