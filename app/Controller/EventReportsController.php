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
            'recursive' => -1
    );

    public function add($event_id)
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['EventReport'])) {
                $this->request->data['EventReport'] = $this->request->data;
            }
            $report = $this->request->data;
            $validationErrors = $this->EventReport->captureReport($this->Auth->user(), $report);
            if (!empty($validationErrors)) {
                $flashErrorMessage = implode(', ', $errors);
                if ($this->_isRest() || $this->request->is('ajax')) {
                    return $this->RestResponse->saveFailResponse('EventReport', 'add', false, $flashErrorMessage, $this->response->type());
                } else {
                    $this->Flash->error($flashErrorMessage);
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $event_id));
                }
            } else {
                $successMessage = __('Report saved.');
                $this->EventReport->Event->unpublishEvent($event_id);
                if ($this->_isRest()) {
                    $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $this->EventReport->id)));
                    return $this->RestResponse->viewData($report[0], $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return $this->RestResponse->saveSuccessResponse('EventReport', 'add', $this->EventReport->id, false, $successMessage);
                } else {
                    $this->Flash->success($successMessage);
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $report['EventReport']['event_id']));
                }
            }
        }

        $event_id = $this->Toolbox->findIdByUuid($this->EventReport->Event, $event_id);
        if (Validation::uuid($event_id)) {
            $temp = $this->EventReport->Event->find('first', array('recursive' => -1, 'fields' => array('Event.id'), 'conditions' => array('Event.uuid' => $event_id)));
            if (empty($temp)) {
                throw new NotFoundException(__('Invalid event'));
            }
            $event_id = $temp['Event']['id'];
        } elseif (!is_numeric($event_id)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $this->EventReport->Event->fetchEvent($this->Auth->user(), array('eventid' => $event_id));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $this->set('event_id', $event_id);

        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
        $initialDistribution = 5;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $this->set('initialDistribution', $initialDistribution);
        $sgs = $this->EventReport->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'add');
    }


    public function view($report_id, $ajax=false)
    {
        $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $report_id)));
        if (empty($report)) {
            throw new NotFoundException(__('Invalid Event Report'));
        }
        $report = $report[0];
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($report, $this->response->type());
        }
        $proxyMISPElements = $this->EventReport->getProxyMISPElements($this->Auth->user(), $report['EventReport']['event_id']);
        $this->set('proxyMISPElements', $proxyMISPElements);
        $this->set('id', $report_id);
        $this->set('report', $report);
        $this->set('ajax', $ajax);
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
        $canEdit = $this->EventReport->canEditReport($this->Auth->user(), $report) === true;
        $this->set('canEdit', $canEdit);
    }

    public function viewSummary($report_id)
    {
        $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $report_id)));
        if (empty($report)) {
            throw new NotFoundException(__('Invalid Event Report'));
        }
        $report = $report[0];
        $proxyMISPElements = $this->EventReport->getProxyMISPElements($this->Auth->user(), $report['EventReport']['event_id']);
        $this->set('proxyMISPElements', $proxyMISPElements);
        $this->set('id', $report_id);
        $this->set('report', $report);
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
        $canEdit = $this->EventReport->canEditReport($this->Auth->user(), $report) === true;
        $this->set('canEdit', $canEdit);
    }

    public function edit($id)
    {
        $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=true);
        if ($this->request->is('post') || $this->request->is('put')) {
            $newReport = $this->request->data;
            if (!isset($newReport['EventReport'])) {
                $newReport = array('EventReport' => $newReport);
            }
            $fieldList = array('id', 'name', 'content', 'timestamp', 'distribution', 'sharing_group_id', 'deleted');
            foreach ($fieldList as $field) {
                if (!empty($newReport['EventReport'][$field])) {
                    $report['EventReport'][$field] = $newReport['EventReport'][$field];
                }
            }
            $errors = $this->EventReport->editReport($this->Auth->user(), $report);
            if (!empty($errors)) {
                $flashErrorMessage = implode(', ', $errors);
                if ($this->_isRest() || $this->request->is('ajax')) {
                    return $this->RestResponse->saveFailResponse('EventReport', 'edit', $id, $flashErrorMessage, $this->response->type());
                } else {
                    $this->Flash->error($flashErrorMessage);
                    $this->redirect(array('controller' => 'eventReports', 'action' => 'view', $id));
                }
            } else {
                $successMessage = __('The report has been saved');
                if ($this->_isRest()) {
                    $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $id)));
                    return $this->RestResponse->viewData($report[0], $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return $this->RestResponse->saveSuccessResponse('EventReport', 'edit', $this->response->type(), $successMessage);
                } else {
                    $this->Flash->success($successMessage);
                    $this->redirect(array('controller' => 'eventReports', 'action' => 'view', $id));
                }
            }
        } else {
            $this->request->data = $report;
        }

        $this->set('id', $report['EventReport']['id']);
        $this->set('event_id', $report['EventReport']['event_id']);
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
        $initialDistribution = 5;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $this->set('initialDistribution', $initialDistribution);
        $this->loadModel('SharingGroup');
        $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'edit');
        $this->render('add');
    }

    public function delete($id, $hard=false)
    {
        if ($this->request->is('post')) {
            $deleted = $this->EventReport->deleteReport($this->Auth->user(), $id, $hard=$hard);
            if ($deleted) {
                $successMessage = __('Report %s deleted', $hard ? __('hard') : __('soft'));
                if ($this->_isRest()) {
                    $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $id)));
                    return $this->RestResponse->viewData($report[0], $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return $this->RestResponse->saveSuccessResponse('EventReport', 'delete', $id, false, $successMessage);
                } else {
                    $this->Flash->success($successMessage);
                    $this->redirect($this->referer());
                }
            } else {
                if ($this->_isRest() || $this->request->is('ajax')) {
                    return $this->RestResponse->saveFailResponse('EventReport', 'delete', $id, $flashErrorMessage, $this->response->type());
                } else {
                    $this->Flash->error(__('Could not delete report'));
                    $this->redirect($this->referer());
                }
            }
        } else {
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=false);
            if ($this->request->is('ajax')) {
                $this->set('report', $report['EventReport']);
                $this->render('ajax/delete');
            } else {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            }
        }
    }

    public function restore($id)
    {
        if ($this->request->is('post')) {
            $result = $this->EventReport->restoreReport($this->Auth->user(), $id);
            if ($result) {
                $message = __('Report %s successfuly restored.', $id);
                if ($this->_isRest()) {
                    $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $id)));
                    return $this->RestResponse->viewData($report[0], $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return $this->RestResponse->saveSuccessResponse('EventReport', 'restore', $id, $this->response->type());
                } else {
                    $this->Flash->success($message);
                    $this->redirect($this->referer());
                }
            } else {
                $message = __('Report %s could not be restored.', $id);
                if ($this->_isRest()) {
                    $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $id)));
                    return $this->RestResponse->viewData($report[0], $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return $this->RestResponse->saveFailResponse('EventReport', 'restore', $id, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect($this->referer());
                }
            }
        } else {
            throw new MethodNotAllowedException(__('This function can only be reached via POST.'));
        }
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

}
