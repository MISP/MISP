<?php

App::uses('AppController', 'Controller');

class EventReportsController extends AppController
{
    public $components = array(
        'Security',
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
            )
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
        $event = $this->canModifyEvent($eventId);
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['EventReport'])) {
                $this->request->data['EventReport'] = $this->request->data;
            }
            $report = $this->request->data;
            $errors = $this->EventReport->addReport($this->Auth->user(), $report, $eventId);
            $redirectTarget = array('controller' => 'events', 'action' => 'view', $eventId);
            if (!empty($errors)) {
                return $this->getFailResponseBasedOnContext($errors, array(), 'add', $this->EventReport->id, $redirectTarget);
            } else {
                $successMessage = __('Report saved.');
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $this->EventReport->id);
                return $this->getSuccessResponseBasedOnContext($successMessage, $report, 'add', false, $redirectTarget);
            }
        }
        $this->set('event_id', $eventId);
        $this->set('action', 'add');
        $this->injectDistributionLevelToViewContext();
        $this->injectSharingGroupsDataToViewContext();
    }


    public function view($reportId, $ajax=false)
    {
        $report = $this->EventReport->simpleFetchById($this->Auth->user(), $reportId);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($report, $this->response->type());
        }
        $this->set('ajax', $ajax);
        $this->set('id', $reportId);
        $this->set('report', $report);
        $this->injectDistributionLevelToViewContext();
        $this->injectPermissionsToViewContext($this->Auth->user(), $report);
    }

    public function getProxyMISPElements($reportId)
    {
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This function can only be reached via the API.'));
        }
        $report = $this->EventReport->simpleFetchById($this->Auth->user(), $reportId);
        $proxyMISPElements = $this->EventReport->getProxyMISPElements($this->Auth->user(), $report['EventReport']['event_id']);
        return $this->RestResponse->viewData($proxyMISPElements, $this->response->type());
    }

    public function viewSummary($reportId)
    {
        $report = $this->EventReport->simpleFetchById($this->Auth->user(), $reportId);
        $proxyMISPElements = $this->EventReport->getProxyMISPElements($this->Auth->user(), $report['EventReport']['event_id']);
        $this->set('proxyMISPElements', $proxyMISPElements);
        $this->set('id', $reportId);
        $this->set('report', $report);
        $this->injectDistributionLevelToViewContext();
        $this->injectPermissionsToViewContext($this->Auth->user(), $report);
    }

    public function edit($id)
    {
        $savedReport = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=true);
        if ($this->request->is('post') || $this->request->is('put')) {
            $newReport = $this->request->data;
            $newReport = $this->applyDataFromSavedReport($newReport, $savedReport);
            $errors = $this->EventReport->editReport($this->Auth->user(), $newReport, $savedReport['EventReport']['event_id']);
            $redirectTarget = array('controller' => 'eventReports', 'action' => 'view', $id);
            if (!empty($errors)) {
                return $this->getFailResponseBasedOnContext($validationErrors, array(), 'edit', $id, $redirectTarget);
            } else {
                $successMessage = __('Report saved.');
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $this->EventReport->id);
                return $this->getSuccessResponseBasedOnContext($successMessage, $report, 'edit', $id, $redirectTarget);
            }
        } else {
            $this->request->data = $savedReport;
        }

        $this->set('id', $savedReport['EventReport']['id']);
        $this->set('event_id', $savedReport['EventReport']['event_id']);
        $this->set('action', 'edit');
        $this->injectDistributionLevelToViewContext();
        $this->injectSharingGroupsDataToViewContext();
        $this->render('add');
    }

    public function delete($id, $hard=false)
    {
        $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=false);
        if ($this->request->is('post')) {
            $errors = $this->EventReport->deleteReport($this->Auth->user(), $id, $hard=$hard);
            $redirectTarget = $this->referer();
            if (empty($errors)) {
                $successMessage = __('Event Report %s %s deleted', $id, $hard ? __('hard') : __('soft'));
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $id);
                return $this->getSuccessResponseBasedOnContext($successMessage, $report, 'delete', $id, $redirectTarget);
            } else {
                $errorMessage = __('Event Report %s could not be %s deleted.%sReasons: %s', $id, $hard ? __('hard') : __('soft'), PHP_EOL, json_encode($errors));
                return $this->getFailResponseBasedOnContext($errorMessage, array(), 'edit', $id, $redirectTarget);
            }
        } else {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            } else {
                $this->layout = 'ajax';
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
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $id);
                return $this->getSuccessResponseBasedOnContext($successMessage, $report, 'restore', $id, $redirectTarget);
            } else {
                $errorMessage = __('Event Report %s could not be %s restored.%sReasons: %s', $id, PHP_EOL, json_encode($errors));
                return $this->getFailResponseBasedOnContext($errorMessage, array(), 'restore', $id, $redirectTarget);
            }
        } else {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            } else {
                $this->layout = 'ajax';
                $this->set('report', $report);
            }
        }
    }

    public function index()
    {
        $filters = $this->IndexFilter->harvestParameters(['event_id', 'value', 'context', 'index_for_event', 'extended_event']);
        $filters['embedded_view']  = $this->request->is('ajax');
        $compiledConditions = $this->generateIndexConditions($filters);
        if ($this->_isRest()) {
            $reports = $this->EventReport->find('all', [
                'recursive' => -1,
                'conditions' => $compiledConditions,
                'contain' => $this->EventReport->defaultContain,
            ]);
            return $this->RestResponse->viewData($reports, $this->response->type());
        } else {
            $this->paginate['conditions']['AND'][] = $compiledConditions;
            $reports = $this->paginate();
            $this->set('reports', $reports);
            $this->injectIndexVariablesToViewContext($filters);
            if (!empty($filters['index_for_event'])) {
                $this->set('extendedEvent', !empty($filters['extended_event']));
                $this->render('ajax/indexForEvent');
            }
        }
    }

    private function generateIndexConditions($filters = [])
    {
        $aclConditions = $this->EventReport->buildACLConditions($this->Auth->user());
        $eventConditions = [];
        if (!empty($filters['event_id'])) {
            $extendingEvents = [];
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

    private function getSuccessResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
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

    private function getFailResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
    {
        if (is_array($message)) {
            $message = implode(', ', $message);
        }
        if ($this->_isRest()) {
            if (!is_null($data)) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message, false);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message, false, $data);
        } else {
            $this->Flash->error($message);
            $this->redirect($this->referer());
        }
        return;
    }

    private function injectIndexVariablesToViewContext($filters)
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
        $this->injectDistributionLevelToViewContext();
    }

    private function injectDistributionLevelToViewContext()
    {
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
        $initialDistribution = 5;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $this->set('initialDistribution', $initialDistribution);
    }

    private function injectSharingGroupsDataToViewContext()
    {
        $sgs = $this->EventReport->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $this->set('sharingGroups', $sgs);
    }

    private function injectPermissionsToViewContext($user, $report)
    {
        $canEdit = $this->EventReport->canEditReport($user, $report) === true;
        $this->set('canEdit', $canEdit);
    }

    private function canModifyEvent($eventId)
    {
        $event = $this->EventReport->Event->fetchSimpleEvent($this->Auth->user(), $eventId, array());
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        return $event;
    }

    private function applyDataFromSavedReport($newReport, $savedReport)
    {
        if (!isset($newReport['EventReport'])) {
            $newReport = array('EventReport' => $newReport);
        }
        $fieldList = $this->EventReport->captureFields;
        $ignoreFieldList = ['id', 'uuid', 'event_id', 'deleted'];
        foreach ($fieldList as $field) {
            if (!in_array($field, $ignoreFieldList) && isset($newReport['EventReport'][$field])) {
                $savedReport['EventReport'][$field] = $newReport['EventReport'][$field];
            }
        }
        return $savedReport;
    }
}
