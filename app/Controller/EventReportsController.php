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

    public function add($eventId)
    {
        $event = $this->canModifyEvent($eventId);
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['EventReport'])) {
                $this->request->data['EventReport'] = $this->request->data;
            }
            $report = $this->request->data;
            $validationErrors = $this->EventReport->captureReport($this->Auth->user(), $report, $eventId);
            $redirectTarget = array('controller' => 'events', 'action' => 'view', $eventId);
            if (!empty($validationErrors)) {
                return $this->getFailResponseBasedOnContext($validationErrors, array(), 'add', $this->EventReport->id, $redirectTarget);
            } else {
                $successMessage = __('Report saved.');
                $this->EventReport->Event->unpublishEvent($eventId);
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
        $proxyMISPElements = $this->EventReport->getProxyMISPElements($this->Auth->user(), $report['EventReport']['event_id']);
        $this->set('proxyMISPElements', $proxyMISPElements);
        $this->set('id', $reportId);
        $this->set('report', $report);
        $this->set('ajax', $ajax);
        $this->injectDistributionLevelToViewContext();
        $this->injectPermissionsToViewContext($this->Auth->user(), $report);
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
            $errors = $this->EventReport->editReport($this->Auth->user(), $newReport, $newReport['EventReport']['event_id']);
            $redirectTarget = array('controller' => 'eventReports', 'action' => 'view', $id);
            if (!empty($errors)) {
                return $this->getFailResponseBasedOnContext($validationErrors, array(), 'edit', $id, $redirectTarget);
            } else {
                $successMessage = __('Report saved.');
                $this->EventReport->Event->unpublishEvent($report['EventReport']['event_id']);
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $this->EventReport->id);
                return $this->getSuccessResponseBasedOnContext($successMessage, $report, 'edit', $id, $redirectTarget);
            }
        } else {
            $this->request->data = $savedReport;
        }

        $this->set('id', $savedReport['EventReport']['id']);
        $this->set('event_id', $savedReport['EventReport']['event_id']);
        $this->set('action', 'edit');
        $this->render('add');
        $this->injectDistributionLevelToViewContext();
        $this->injectSharingGroupsDataToViewContext();
    }

    public function delete($id, $hard=false)
    {
        $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=false);
        if ($this->request->is('post')) {
            $deleted = $this->EventReport->deleteReport($this->Auth->user(), $id, $hard=$hard);
            $redirectTarget = $this->referer();
            if ($deleted) {
                $successMessage = __('Report %s %s deleted', $id, $hard ? __('hard') : __('soft'));
                $this->EventReport->Event->unpublishEvent($report['EventReport']['event_id']);
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $id);
                return $this->getSuccessResponseBasedOnContext($successMessage, $report, 'delete', $id, $redirectTarget);
            } else {
                $errorMessage = __('Report %s could not be %s deleted', $id, $hard ? __('hard') : __('soft'));
                return $this->getFailResponseBasedOnContext($errorMessage, array(), 'edit', $id, $redirectTarget);
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

    public function restore($id)
    {
        $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=false);
        if ($this->request->is('post')) {
            $restored = $this->EventReport->restoreReport($this->Auth->user(), $id);
            $redirectTarget = $this->referer();
            if ($restored) {
                $successMessage = __('Report %s restored', $id);
                $this->EventReport->Event->unpublishEvent($report['EventReport']['event_id']);
                $report = $this->EventReport->simpleFetchById($this->Auth->user(), $id);
                return $this->getSuccessResponseBasedOnContext($successMessage, $report, 'restore', $id, $redirectTarget);
            } else {
                $errorMessage = __('Report could not be %s restored', $id);
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

    private function getIndexConditions()
    {
        // add confitions here
    }

    public function index()
    {
        $aclConditions = $this->EventReport->buildConditions($this->Auth->user());
        $filters = $this->IndexFilter->harvestParameters(array('event_id', 'embedded_view', 'value', 'context'));
        $eventConditions = array();
        if (!empty($filters['event_id'])) {
            $eventConditions = array(
                'EventReport.event_id' => $filters['event_id']
            );
        }

        $contextConditions = array();
        if (empty($filters['context'])) {
            $filters['context'] = 'default';
        }
        if ($filters['context'] == 'deleted') {
            $contextConditions['EventReport.deleted'] = true;
        } elseif ($filters['context'] == 'default') {
            $contextConditions['EventReport.deleted'] = false;
        }
        $this->set('context', $filters['context']);

        $searchConditions = array();
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
        if ($this->_isRest()) {
            $reports = $this->EventReport->find('all', 
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($eventConditions, $searchConditions, $aclConditions, $contextConditions)
                    )
                )
            );
            return $this->RestResponse->viewData($reports, $this->response->type());
        } else {
            $this->set('embedded_view', !empty($this->params['named']['embedded_view']));
            $this->paginate['conditions']['AND'][] = $eventConditions;
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $this->paginate['conditions']['AND'][] = $contextConditions;
            $reports = $this->paginate();
            $this->set('reports', $reports);
            if (!empty($filters['event_id'])) {
                $this->set('event_id', $filters['event_id']);
            }
            $this->set('searchall', $filters['value']);
            $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
            $this->set('distributionLevels', $distributionLevels);
        }
    }

    public function eventIndex($event_id)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
        }
        $aclConditions = $this->EventReport->buildConditions($this->Auth->user());
        $filters = $this->IndexFilter->harvestParameters(array('context'));
        $eventConditions = array();
        $eventConditions = array(
            'EventReport.event_id' => $event_id
        );

        $contextConditions = array();
        if (empty($filters['context'])) {
            $filters['context'] = 'default';
        }
        if ($filters['context'] == 'deleted') {
            $contextConditions['EventReport.deleted'] = true;
        } elseif ($filters['context'] == 'default') {
            $contextConditions['EventReport.deleted'] = false;
        }
        $this->set('context', $filters['context']);
        $this->paginate['conditions']['AND'][] = $eventConditions;
        $this->paginate['conditions']['AND'][] = $aclConditions;
        $this->paginate['conditions']['AND'][] = $contextConditions;
        $reports = $this->paginate();
        $this->set('reports', $reports);
        $this->set('event_id', $event_id);
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
        $this->render('ajax/index');
    }

    private function getSuccessResponseBasedOnContext($message, array $data = array(), $action = '', $id = false, $redirect = array())
    {
        if ($this->_isRest()) {
            if (!empty($data)) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveSuccessResponse($this->alias, $action, $id, false, $message);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveSuccessResponse($this->alias, $action, $id, false, $message);
        } else {
            $this->Flash->success($message);
            $this->redirect($redirect);
        }
        return;
    }

    private function getFailResponseBasedOnContext($message, array $data = array(), $action = '', $id = false, $redirect = array())
    {
        if (is_array($message)) {
            $message = implode(', ', $message);
        }
        if ($this->_isRest()) {
            if (!empty($data)) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message, false);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message, false);
        } else {
            $this->Flash->error($message);
            $this->redirect($this->referer());
        }
        return;
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
        foreach ($fieldList as $field) {
            if (!empty($newReport['EventReport'][$field])) {
                $savedReport['EventReport'][$field] = $newReport['EventReport'][$field];
            }
        }
        return $savedReport;
    }
}
