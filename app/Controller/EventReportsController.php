<?php
App::uses('AppController', 'Controller');

/**
 * @property EventReport $EventReport
 */
class EventReportsController extends AppController
{
    public $components = array(
        'AdminCrud',
        'RequestHandler'
    );

    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'EventReport.event_id' => 'ASC',
            'EventReport.name' => 'ASC'
        ),
        'recursive' => -1,
        'contain' => array(
            'SharingGroup' => array('fields' => array('id', 'name', 'uuid')),
            'Event' => array(
                'fields' =>  array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.info', 'Event.user_id', 'Event.date'),
                'Orgc' => array('fields' => array('Orgc.id', 'Orgc.name')),
                'Org' => array('fields' => array('Org.id', 'Org.name'))
            ),
            'EventReportTag' => [
                'Tag'
            ]
        )
    );

    public function add($eventId = false)
    {
        if ($this->request->is('get') && $this->_isRest()) {
            return $this->RestResponse->describe('EventReports', 'add', false, $this->response->type());
        }
        if ($eventId === false) {
            throw new MethodNotAllowedException(__('No event ID set.'));
        }
        $event = $this->__canModifyReport($eventId);
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['EventReport'])) {
                $this->request->data['EventReport'] = $this->request->data;
            }
            $report = $this->request->data;
            $errors = $this->EventReport->addReport($this->Auth->user(), $report, $eventId);
            $redirectTarget = array('controller' => 'events', 'action' => 'view', $eventId);
            if (!empty($errors)) {
                return $this->__getFailResponseBasedOnContext($errors, null, 'add', $this->EventReport->id, $redirectTarget);
            } else {
                $successMessage = __('Report saved.');
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $this->EventReport->id);
                return $this->__getSuccessResponseBasedOnContext($successMessage, $report, 'add', false, $redirectTarget);
            }
        }
        $this->set('event_id', $eventId);
        $this->set('action', 'add');
        $this->__injectDistributionLevelToViewContext();
        $this->__injectSharingGroupsDataToViewContext();
    }


    public function view($reportId, $ajax=false)
    {
        $this->EventReport->includeAnalystData = true;
        $this->EventReport->includeAnalystDataRecursive = true;
        $report = $this->EventReport->simpleFetchById($this->Auth->user(), $reportId);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($report, $this->response->type());
        }
        $this->set('ajax', $ajax);
        $this->set('id', $reportId);
        $this->set('report', $report);
        $this->set('title_for_layout', __('Event report %s', $report['EventReport']['name']));
        $this->__injectDistributionLevelToViewContext();
        $this->__injectPermissionsToViewContext($this->Auth->user(), $report);
    }

    public function getProxyMISPElements($reportId)
    {
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This function can only be reached via the API.'));
        }
        $user = $this->_closeSession();
        $report = $this->EventReport->simpleFetchById($user, $reportId);
        $proxyMISPElements = $this->EventReport->getProxyMISPElements($user, $report['EventReport']['event_id']);
        return $this->RestResponse->viewData($proxyMISPElements, $this->response->type());
    }

    public function viewSummary($reportId)
    {
        $report = $this->EventReport->simpleFetchById($this->Auth->user(), $reportId);
        $this->set('id', $reportId);
        $this->set('report', $report);
        $this->__injectDistributionLevelToViewContext();
        $this->__injectPermissionsToViewContext($this->Auth->user(), $report);
    }

    public function edit($id)
    {
        $savedReport = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=true);
        if ($this->request->is('post') || $this->request->is('put')) {
            $newReport = $this->request->data;
            $newReport = $this->__applyDataFromSavedReport($newReport, $savedReport);
            $errors = $this->EventReport->editReport($this->Auth->user(), $newReport, $savedReport['EventReport']['event_id']);
            $redirectTarget = array('controller' => 'eventReports', 'action' => 'view', $id);
            if (!empty($errors)) {
                return $this->__getFailResponseBasedOnContext($validationErrors, array(), 'edit', $id, $redirectTarget);
            } else {
                $successMessage = __('Report saved.');
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $this->EventReport->id);
                return $this->__getSuccessResponseBasedOnContext($successMessage, $report, 'edit', $id, $redirectTarget);
            }
        } else {
            $this->request->data = $savedReport;
        }

        $this->set('id', $savedReport['EventReport']['id']);
        $this->set('event_id', $savedReport['EventReport']['event_id']);
        $this->set('action', 'edit');
        $this->__injectDistributionLevelToViewContext();
        $this->__injectSharingGroupsDataToViewContext();
        $this->render('add');
    }

    public function delete($id, $hard=false)
    {
        $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'delete', $throwErrors=true, $full=false);
        if ($this->request->is('post')) {
            if (!empty($this->request->data['hard'])) {
                $hard = true;
            }
            $errors = $this->EventReport->deleteReport($this->Auth->user(), $report, $hard);
            $redirectTarget = $this->referer();
            if (empty($errors)) {
                $successMessage = __('Event Report %s %s deleted', $id, $hard ? __('hard') : __('soft'));
                return $this->__getSuccessResponseBasedOnContext($successMessage, null, 'delete', $id, $redirectTarget);
            } else {
                $errorMessage = __('Event Report %s could not be %s deleted.%sReasons: %s', $id, $hard ? __('hard') : __('soft'), PHP_EOL, json_encode($errors));
                return $this->__getFailResponseBasedOnContext($errorMessage, array(), 'edit', $id, $redirectTarget);
            }
        } else {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            } else {
                $this->layout = false;
                $this->set('report', $report);
                $this->render('ajax/delete');
            }
        }
    }

    public function restore($id)
    {
        $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=false);
        if ($this->request->is('post')) {
            $errors = $this->EventReport->restoreReport($this->Auth->user(), $id);
            $redirectTarget = $this->referer();
            if (empty($errors)) {
                $successMessage = __('Event Report %s restored', $id);
                return $this->__getSuccessResponseBasedOnContext($successMessage, null, 'restore', $id, $redirectTarget);
            } else {
                $errorMessage = __('Event Report %s could not be %s restored.%sReasons: %s', $id, PHP_EOL, json_encode($errors));
                return $this->__getFailResponseBasedOnContext($errorMessage, array(), 'restore', $id, $redirectTarget);
            }
        } else {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            } else {
                $this->layout = false;
                $this->set('report', $report);
            }
        }
    }

    public function addTag($id = false, $tag_id = false)
    {
        $local = empty($this->request->params['named']['local']) ? 0 : 1;
        if (!$this->request->is('post')) {
            if ($id === false) {
                throw new NotFoundException(__('Invalid report'));
            }
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=false);
            $this->set('local', $local);
            $this->set('object_id', $id);
            $this->set('scope', 'EventReport');
            $this->layout = false;
            $this->autoRender = false;
            $this->render('/Events/add_tag');
        } else {
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=false);
            if ($tag_id === false) {
                if (!isset($this->request->data['EventReport']['tag'])) {
                    throw new NotFoundException(__('Invalid tag'));
                }
                $tag_id = $this->request->data['EventReport']['tag'];
            }
            if (!is_numeric($tag_id)) {
                if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                    $tagChoice = explode('_', $tag_id)[1];
                    $this->loadModel('TagCollection');
                    $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), ['conditions' => ['TagCollection.id' => $tagChoice]]);
                    if (empty($tagCollection)) {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag Collection.')), 'status'=>200, 'type' => 'json'));
                    }
                    $tag_id_list = array_column($tagCollection[0]['TagCollectionTag'], 'tag_id');
                } else {
                    // try to parse json array
                    $tag_ids = json_decode($tag_id);
                    if ($tag_ids !== null) { // can decode json
                        $tag_id_list = [];
                        foreach ($tag_ids as $tag_id) {
                            if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                                $tagChoice = explode('_', $tag_id)[1];
                                $this->loadModel('TagCollection');
                                $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), ['conditions' => ['TagCollection.id' => $tagChoice]]);
                                if (empty($tagCollection)) {
                                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag Collection.')), 'status'=>200, 'type' => 'json'));
                                }
                                $tag_id_list = array_column($tagCollection[0]['TagCollectionTag'], 'tag_id');
                            } else {
                                $tag_id_list[] = $tag_id;
                            }
                        }
                    } else {
                        $tagId = $this->EventReports->EventReportTag->Tag->lookupTagIdForUser($this->Auth->user(), trim($tag_id));
                        if (empty($tagId)) {
                            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status'=>200, 'type' => 'json'));
                        }
                        $tag_id = $tagId;
                    }
                }
            }
            if (empty($tag_id_list)) {
                $tag_id_list = [$tag_id];
            }
            $saveResult = $this->EventReport->EventReportTag->attachTags($this->Auth->user(), $id, $tag_id_list, $local);
            $fails = $saveResult['fails'];
            $successes = $saveResult['successes'];
            if ($fails === 0) {
                $message = __n('Tag added.', '%s tags added', $successes, $successes);
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message, 'check_publish' => true)), 'status' => 200, 'type' => 'json'));
            } else {
                $message = __n('Tag could not be added.', '%s tags could not be added.', $fails, $fails);
                if ($successes > 0) {
                    $message .= __n(' However, %s tag was added.', ' However, %s tags were added.', $successes, $successes);
                }
                return new CakeResponse(array('body' => json_encode(array('saved' => false, 'errors' => $message)), 'status' => 200, 'type' => 'json'));
            }
        }
    }

    public function removeTag($id = false, $tag_id = false, $galaxy = false)
    {
        $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', true, false);
        if (!$this->request->is('post')) {
            $reportTag = $this->EventReport->EventReportTag->find('first', array(
                'conditions' => array(
                    'event_report_id' => $report['EventReport']['id'],
                    'tag_id' => $tag_id,
                ),
                'contain' => ['Tag'],
                'recursive' => -1,
            ));
            if (!$reportTag) {
                throw new NotFoundException(__('Invalid tag.'));
            }
            $this->set('is_local', $reportTag['EventReportTag']['local']);
            $this->set('tag', $reportTag);
            $this->set('id', $report['EventReport']['id']);
            $this->set('tag_id', $tag_id);
            $this->set('model', 'event_report');
            $this->set('model_name', $report['EventReport']['name']);
            $this->render('/Attributes/ajax/tagRemoveConfirmation');
        } else {
            if ($id === false) {
                $id = $this->request->data['event'];
            }
            if ($tag_id === false) {
                $tag_id = $this->request->data['tag'];
            }
            if (empty($tag_id)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid ' . ($galaxy ? 'Galaxy' : 'Tag') . '.')), 'status'=>200, 'type' => 'json'));
            }
            if (!is_numeric($tag_id)) {
                $tag = $this->EventReport->EventReportTag->Tag->find('first', array('recursive' => -1, 'conditions' => array('LOWER(Tag.name) LIKE' => strtolower(trim($tag_id)))));
                if (empty($tag)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid ' . ($galaxy ? 'Galaxy' : 'Tag') . '.')), 'status'=>200, 'type' => 'json'));
                }
                $tag_id = $tag['Tag']['id'];
            }
            if (!is_numeric($id)) {
                $id = $this->request->data['EventReport']['id'];
            }
            $eventReportTag = $this->EventReport->EventReportTag->find('first', array(
                'conditions' => array(
                    'event_report_id' => $id,
                    'tag_id' => $tag_id
                ),
                'recursive' => -1,
            ));
            if (!$eventReportTag) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid event-report - ' . ($galaxy ? 'galaxy' : 'tag') . ' combination.')), 'status'=>200, 'type' => 'json'));
            }
            $event = ['Event' => $report['Event']];
            // org should allow to (un)tag too, so that an event that gets pushed can be (un)tagged locally by the owning org
            if (!$this->__canModifyTag($event, $eventReportTag['EventReportTag']['local'])) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
            }
            $tag = $this->EventReport->EventReportTag->Tag->find('first', array(
                'conditions' => array('Tag.id' => $tag_id),
                'recursive' => -1,
                'fields' => array('Tag.name')
            ));
            if ($this->EventReport->EventReportTag->delete($eventReportTag['EventReportTag']['id'])) {
                if (empty($eventReportTag['EventReportTag']['local'])) {
                    $this->EventReport->Event->unpublishEvent($event);
                }
                $log = ClassRegistry::init('Log');
                $log->createLogEntry($this->Auth->user(), 'tag', 'EventReport', $id, 'Removed tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" from event-report (' . $id . ')', 'EventReport (' . $id . ') untagged of Tag (' . $tag_id . ')');
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => ($galaxy ? 'Galaxy' : 'Tag') . ' removed.', 'check_publish' => empty($eventReportTag['EventReportTag']['local']))), 'status'=>200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => ($galaxy ? 'Galaxy' : 'Tag') . ' could not be removed.')), 'status'=>200, 'type' => 'json'));
            }
        }
    }

    public function index()
    {
        $filters = $this->IndexFilter->harvestParameters(['event_id', 'value', 'context', 'index_for_event', 'extended_event']);
        $filters['embedded_view']  = $this->request->is('ajax');
        $compiledConditions = $this->__generateIndexConditions($filters);
        $this->EventReport->includeAnalystData = true;
        if ($this->_isRest()) {
            $reports = $this->EventReport->find('all', [
                'recursive' => -1,
                'conditions' => $compiledConditions,
                'contain' => EventReport::DEFAULT_CONTAIN,
            ]);
            return $this->RestResponse->viewData($reports, $this->response->type());
        } else {
            $this->paginate['conditions']['AND'][] = $compiledConditions;
            $reports = $this->paginate();
            $reports = $this->moveTagLocality($reports);
            $this->set('reports', $reports);
            $this->__injectIndexVariablesToViewContext($filters);
            if (!empty($filters['index_for_event'])) {
                if (empty($filters['event_id'])) {
                    throw new MethodNotAllowedException("When requesting index for event, event ID must be provided.");
                }
                try {
                    $this->__canModifyReport($filters['event_id']);
                    $canModify = true;
                } catch (Exception $e) {
                    $canModify = false;
                }
                $this->set('canModify', $canModify);
                $this->set('extendedEvent', !empty($filters['extended_event']));
                $fetcherModule = $this->EventReport->isFetchURLModuleEnabled();
                $this->set('importModuleEnabled', is_array($fetcherModule));
                $this->render('ajax/indexForEvent');
            } else {
                $this->set('title_for_layout', __('Event Reports'));
            }
        }
    }

    private function moveTagLocality(array $reports): array
    {
        foreach ($reports as $i => $report) {
            foreach ($report['EventReportTag'] as $j => $reportTag) {
                $reports[$i]['EventReportTag'][$j]['Tag']['local'] = $reportTag['local'];
            }
        }
        return $reports;
    }

    public function extractAllFromReport($reportId)
    {
        if (!$this->request->is('ajax') && !$this->_isRest()) {
            throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
        }
        if ($this->request->is('post')) {
            if (!isset($this->data['EventReport'])) {
                $this->data = ['EventReport' => $this->data];
            }
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $reportId, 'edit', $throwErrors=true, $full=false);
            $results = $this->EventReport->getComplexTypeToolResultWithReplacements($this->Auth->user(), $report);
            $report['EventReport']['content'] = $results['replacementResult']['contentWithReplacements'];
            $contextResults = $this->EventReport->extractWithReplacements($this->Auth->user(), $report, ['replace' => true]);
            $suggestionResult = $this->EventReport->transformFreeTextIntoSuggestion($contextResults['contentWithReplacements'], $results['complexTypeToolResult']);
            $errors = $this->EventReport->applySuggestions($this->Auth->user(), $report, $suggestionResult['contentWithSuggestions'], $suggestionResult['suggestionsMapping']);
            if (empty($errors)) {
                if (!empty($this->data['EventReport']['tag_event'])) {
                    $this->EventReport->attachTagsAfterReplacements($this->Auth->User(), $contextResults['replacedContext'], $report['EventReport']['event_id']);
                }
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $reportId);
                $data = [ 'report' => $report ];
                $successMessage = __('Automatic extraction applied to Event Report %s', $reportId);
                return $this->__getSuccessResponseBasedOnContext($successMessage, $data, 'applySuggestions', $reportId);
            } else {
                $errorMessage = __('Automatic extraction could not be applied to Event Report %s.%sReasons: %s', $reportId, PHP_EOL, json_encode($errors));
                return $this->__getFailResponseBasedOnContext($errorMessage, array(), 'applySuggestions', $reportId);
            }
        }
        $this->layout = false;
        $this->set('reportId', $reportId);
        $this->render('ajax/extractAllFromReport');
    }

    public function extractFromReport($reportId)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
        } else {
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $reportId, 'view', $throwErrors=true, $full=false);
            $dataResults = $this->EventReport->getComplexTypeToolResultWithReplacements($this->Auth->user(), $report);
            $report['EventReport']['content'] = $dataResults['replacementResult']['contentWithReplacements'];
            $contextResults = $this->EventReport->extractWithReplacements($this->Auth->user(), $report);
            $typeToCategoryMapping = $this->EventReport->Event->Attribute->typeToCategoryMapping();
            $data = [
                'complexTypeToolResult' => $dataResults['complexTypeToolResult'],
                'typeToCategoryMapping' => $typeToCategoryMapping,
                'replacementValues' => $dataResults['replacementResult']['replacedValues'],
                'replacementContext' => $contextResults['replacedContext']
            ];
            return $this->RestResponse->viewData($data, $this->response->type());
        }
    }

    public function replaceSuggestionInReport($reportId)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
        } else {
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $reportId, 'edit', $throwErrors=true, $full=false);
            if ($this->request->is('post')) {
                $errors = [];
                $suggestions = $this->_jsonDecode($this->data['EventReport']['suggestions']);
                if (!empty($suggestions['content']) && !empty($suggestions['mapping'])) {
                    $errors = $this->EventReport->applySuggestions($this->Auth->user(), $report, $suggestions['content'], $suggestions['mapping']);
                } else {
                    $errors[] = __('`content` and `mapping` key cannot be empty');
                }
                if (empty($errors)) {
                    $report = $this->EventReport->simpleFetchById($this->Auth->user(), $reportId);
                    $results = $this->EventReport->getComplexTypeToolResultWithReplacements($this->Auth->user(), $report);
                    $contextResults = $this->EventReport->extractWithReplacements($this->Auth->user(), $report);
                    $data = [
                        'report' => $report,
                        'complexTypeToolResult' => $results['complexTypeToolResult'],
                        'replacementValues' => $results['replacementResult']['replacedValues'],
                        'replacementContext' => $contextResults['replacedContext']
                    ];
                    $successMessage = __('Suggestions applied to Event Report %s', $reportId);
                    return $this->__getSuccessResponseBasedOnContext($successMessage, $data, 'applySuggestions', $reportId);
                } else {
                    $errorMessage = __('Suggestions could not be applied to Event Report %s.%sReasons: %s', $reportId, PHP_EOL, json_encode($errors));
                    return $this->__getFailResponseBasedOnContext($errorMessage, array(), 'applySuggestions', $reportId);
                }
            }
            $this->layout = false;
            $this->render('ajax/replaceSuggestionInReport');
        }
    }

    public function importReportFromUrl($event_id)
    {
        if (!$this->request->is('ajax') && !$this->_isRest()) {
            throw new MethodNotAllowedException(__('This function can only be reached via AJAX and via the API.'));
        }
        $fetcherModule = $this->EventReport->isFetchURLModuleEnabled();
        if ($this->request->is('post')) {
            if (empty($this->data['EventReport'])) {
                $this->data = ['EventReport' => $this->data];
            }
            if (empty($this->data['EventReport']['url'])) {
                throw new MethodNotAllowedException(__('A URL must be provided'));
            }
            $url = $this->data['EventReport']['url'];
            $format = 'html';
            
            $parsed_formats = ['pdf', 'xlsx', 'pptx', 'ods', 'odt', 'docx'];
            foreach ($parsed_formats as $parsed_format) {
                if (substr($url, -(1 + strlen($parsed_format))) === '.' . $parsed_format) {
                    $format = $parsed_format;
                }
            }
            $content = $this->EventReport->downloadMarkdownFromURL($event_id, $url, $format);

            $errors = [];
            if (!empty($content)) {
                $report = [
                    'name' => __('Report from - %s (%s)', $url, time()),
                    'distribution' => 5,
                    'content' => $content
                ];
                $errors = $this->EventReport->addReport($this->Auth->user(), $report, $event_id);
            } else {
                $errors[] = __('Could not fetch report from URL. Fetcher module not enabled or could not download the page');
            }
            $redirectTarget = array('controller' => 'events', 'action' => 'view', $event_id);
            if (!empty($errors)) {
                return $this->__getFailResponseBasedOnContext($errors, array(), 'addFromURL', $this->EventReport->id, $redirectTarget);
            } else {
                $successMessage = __('Report downloaded and created');
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $this->EventReport->id);
                return $this->__getSuccessResponseBasedOnContext($successMessage, $report, 'addFromURL', false, $redirectTarget);
            }
        }
        $this->set('importModuleEnabled', is_array($fetcherModule));
        $this->set('event_id', $event_id);
        $this->layout = false;
        $this->render('ajax/importReportFromUrl');
    }

    public function reportFromEvent($eventId)
    {
        $event = $this->__canModifyReport($eventId);
        if ($this->request->is('post') || $this->request->is('put')) {
            $filters = $this->_jsonDecode($this->data['EventReport']['filters']);
            $options['conditions'] = $filters;
            $options['conditions'] = array_filter($filters, function($v) {
                return $v !== '';
            });
            $options['event_id'] = $eventId;
            App::uses('ReportFromEvent', 'EventReport');
            $optionFields = array_keys((new ReportFromEvent())->acceptedOptions);
            foreach ($optionFields as $field) {
                if (isset($this->data['EventReport'][$field])) {
                    $options[$field] = $this->data['EventReport'][$field];
                }
            }
            $markdown = $this->EventReport->getReportFromEvent($this->Auth->user(), $options);
            if (!empty($markdown)) {
                $report = [
                    'name' => __('Event report (%s)', time()),
                    'distribution' => 5,
                    'content' => $markdown
                ];
                $errors = $this->EventReport->addReport($this->Auth->user(), $report, $eventId);
            } else {
                $errors[] = __('Could not generate markdown from the event');
            }
            $redirectTarget = array('controller' => 'events', 'action' => 'view', $eventId);
            if (!empty($errors)) {
                return $this->__getFailResponseBasedOnContext($errors, array(), 'add', $this->EventReport->id, $redirectTarget);
            } else {
                $successMessage = __('Report saved.');
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $this->EventReport->id);
                return $this->__getSuccessResponseBasedOnContext($successMessage, $report, 'add', false, $redirectTarget);
            }
        }
        $this->set('event_id', $eventId);
        $this->layout = false;
        $this->render('ajax/reportFromEvent');
    }

    public function sendToLLM($reportId)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
        } else {
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $reportId, 'edit', true, false);
            if ($this->request->is('post')) {
                $errors = [];
                $result = $this->EventReport->sendToLLM($report, $this->Auth->user(), $errors);
                if ($result !== false) {
                    $successMessage = __('Successfully sent to Event Report %s to LLM', $reportId);
                    return $this->__getSuccessResponseBasedOnContext($successMessage, $result, 'sendToLLM', $reportId);
                } else {
                    $errorMessage = __('Could not send Event Report %s to LLM.%sReasons: %s', $reportId, PHP_EOL, json_encode($errors));
                    return $this->__getFailResponseBasedOnContext($errorMessage, array(), 'sendToLLM', $reportId);
                }
            }
            $this->layout = false;
            $this->render('ajax/sendToLLM');
        }
    }

    private function __generateIndexConditions($filters = [])
    {
        $aclConditions = $this->EventReport->buildACLConditions($this->Auth->user());
        $eventConditions = [];
        if (!empty($filters['event_id'])) {
            $extendingEventIds = [];
            if (!empty($filters['extended_event'])) {
                $extendingEventIds = $this->EventReport->Event->getExtendingEventIdsFromEvent($this->Auth->user(), $filters['event_id']);
            }
            $eventConditions = ['EventReport.event_id' => array_merge([$filters['event_id']], $extendingEventIds)];
        }

        $contextConditions = [];
        if (empty($filters['context'])) {
            $filters['context'] = 'default';
        }
        if ($filters['context'] == 'deleted') {
            $contextConditions['EventReport.deleted'] = true;
        } elseif ($filters['context'] == 'default') {
            $contextConditions['EventReport.deleted'] = false;
        }
        $searchConditions = [];
        if (empty($filters['value'])) {
            $filters['value'] = '';
        } else {
            $searchall = '%' . strtolower($filters['value']) . '%';
            $searchConditions = array(
                'OR' => array(
                    'LOWER(EventReport.name) LIKE' => $searchall,
                    'LOWER(EventReport.content) LIKE' => $searchall,
                    'EventReport.id' => $searchall,
                    'EventReport.uuid' => $searchall
                )
            );
        }
        $compiledConditions = [
            'AND' => [
                $aclConditions,
                $eventConditions,
                $contextConditions,
                $searchConditions,
            ]
        ];
        return $compiledConditions;
    }

    private function __getSuccessResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
    {
        if ($this->_isRest()) {
            if (!is_null($data)) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveSuccessResponse($this->EventReport->alias, $action, $id, false, $message);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveSuccessResponse($this->EventReport->alias, $action, $id, false, $message, $data);
        } else {
            $this->Flash->success($message);
            $this->redirect($redirect);
        }
        return;
    }

    private function __getFailResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
    {
        if (is_array($message)) {
            $message = implode(', ', $message);
        }
        if ($this->_isRest()) {
            if ($data !== null) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message, false, $data);
        } else {
            $this->Flash->error($message);
            $this->redirect($this->referer());
        }
    }

    private function __injectIndexVariablesToViewContext($filters)
    {
        if (!empty($filters['context'])) {
            $this->set('context', $filters['context']);
        } else {
            $this->set('context', 'default');
        }
        if (!empty($filters['event_id'])) {
            $this->set('event_id', $filters['event_id']);
        }
        if (isset($filters['embedded_view'])) {
            $this->set('embedded_view', $filters['embedded_view']);
        } else {
            $this->set('embedded_view', false);
        }
        if (!empty($filters['value'])) {
            $this->set('searchall', $filters['value']);
        } else {
            $this->set('searchall', '');
        }
        $this->__injectDistributionLevelToViewContext();
    }

    private function __injectDistributionLevelToViewContext()
    {
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
        $this->set('shortDist', $this->EventReport->Event->Attribute->shortDist);
        $this->set('initialDistribution', $this->EventReport->Event->Attribute->defaultDistribution());
    }

    private function __injectSharingGroupsDataToViewContext()
    {
        $sgs = $this->EventReport->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $this->set('sharingGroups', $sgs);
    }

    private function __injectPermissionsToViewContext(array $user, array $report)
    {
        $canEdit = $this->ACL->canEditEventReport($user, $report);
        $this->set('canEdit', $canEdit);
    }

    /**
     * @param int $eventId
     * @return array
     * @throws NotFoundException
     * @throws ForbiddenException
     */
    private function __canModifyReport($eventId)
    {
        $event = $this->EventReport->Event->fetchSimpleEvent($this->Auth->user(), $eventId);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        return $event;
    }

    private function __applyDataFromSavedReport($newReport, $savedReport)
    {
        if (!isset($newReport['EventReport'])) {
            $newReport = array('EventReport' => $newReport);
        }
        $ignoreFieldList = ['id', 'uuid', 'event_id', 'deleted'];
        foreach (EventReport::CAPTURE_FIELDS as $field) {
            if (!in_array($field, $ignoreFieldList) && isset($newReport['EventReport'][$field])) {
                $savedReport['EventReport'][$field] = $newReport['EventReport'][$field];
            }
        }
        $this->loadModel('AnalystData');
        foreach ($this->AnalystData::ANALYST_DATA_TYPES as $type) {
            if (!empty($newReport['EventReport'][$type])) {
                $savedReport['EventReport'][$type] = $newReport['EventReport'][$type];
            }
        }
        return $savedReport;
    }
}
