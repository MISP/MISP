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
                $flashErrorMessage = implode(', ', $validationErrors);
                $this->Flash->error($flashErrorMessage);
            } else {
                $this->EventReport->Event->unpublishEvent($event_id);
                $this->Flash->success(__('Report saved.'));
                $this->redirect(array('controller' => 'events', 'action' => 'view', $report['EventReport']['event_id']));
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
    }


    public function view($report_id)
    {
    }

    public function edit($id)
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $report = $this->request->data;
            $errors = $this->EventReport->editReport($this->Auth->user(), $report);
                if (!empty($errors)) {
                    $flashErrorMessage = implode(', ', $errors);
                    $this->Flash->error($flashErrorMessage);
                } else {
                    $this->redirect(array('controller' => 'eventReports', 'action' => 'view', $report['EventReport']['id']));
                }
        } else {
            $report_id = $this->Toolbox->findIdByUuid($this->EventReport, $id);
            if (Validation::uuid($report_id)) {
                $temp = $this->EventReport->find('first', array('recursive' => -1, 'fields' => array('EventReport.id'), 'conditions' => array('EventReport.uuid' => $report_id)));
                if (empty($temp)) {
                    throw new NotFoundException(__('Invalid Event Report'));
                }
                $report_id = $temp['Event']['id'];
            } elseif (!is_numeric($id)) {
                throw new NotFoundException(__('Invalid Event Report'));
            }
            $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $report_id)));
            if (empty($report)) {
                throw new NotFoundException(__('Invalid event'));
            }
            $report = $report[0];
            $this->request->data = $report;
        }

        $this->set('event_id', $report['EventReport']['event_id']);
        $this->loadModel('Attribute');
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

    public function delete($id)
    {
    }


    public function index()
    {
        $aclConditions = $this->EventReport->buildConditions($this->Auth->user());
        $filters = $this->IndexFilter->harvestParameters(array('event_id', 'embedded_view', 'value'));
        $eventConditions = array();
        if (!empty($filters['event_id'])) {
            $eventConditions = array(
                'EventReport.event_id' => $filters['event_id']
            );
        }
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
            $reports = $this->EventReports->find('all', 
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($eventConditions, $searchConditions, $aclConditions)
                    )
                )
            );
            return $this->RestResponse->viewData($galaxies, $this->response->type());
        } else {
            $this->set('embedded_view', !empty($this->params['named']['embedded_view']));
            $this->paginate['conditions']['AND'][] = $eventConditions;
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $reports = $this->paginate();
            $this->set('reports', $reports);
            if (!empty($filters['event_id'])) {
                $this->set('event_id', $filters['event_id']);
            }
            $this->set('searchall', $filters['value']);
        }
    }

}
