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
        $this->set('action', 'add');
    }


    public function view($report_id, $ajax=false)
    {
        $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $report_id)));
        if (empty($report)) {
            throw new NotFoundException(__('Invalid Event Report'));
        }
        $report = $report[0];
        $event = $this->EventReport->Event->fetchEvent($this->Auth->user(), ['eventid' => $report['EventReport']['event_id']]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event'));
        }
        $event = $event[0];
        $objects = [];
        $templateConditions = [];
        $recordedConditions = [];
        foreach ($event['Object'] as $k => $object) {
            $objects[$object['id']] = $object;
            $uniqueCondition = sprintf('%s.%s', $object['template_uuid'], $object['template_version']);
            if (!isset($recordedConditions[$uniqueCondition])) {
                $templateConditions['OR'][] = [
                    'ObjectTemplate.uuid' => $object['template_uuid'],
                    'ObjectTemplate.version' => $object['template_version']
                ];
                $recordedConditions[$uniqueCondition] = true;
            }
        }
        $this->loadModel('ObjectTemplate');
        $templates = $this->ObjectTemplate->find('all', array(
            'conditions' => $templateConditions,
            'recursive' => -1,
            'contain' => array(
                'ObjectTemplateElement' => [
                    'order' => ['ui-priority' => 'DESC'],
                    'fields' => ['object_relation', 'type', 'ui-priority']
                ]
            )
        ));
        $objectTemplates = [];
        foreach ($templates as $template) {
            $objectTemplates[sprintf('%s.%s', $template['ObjectTemplate']['uuid'], $template['ObjectTemplate']['version'])] = $template;
        }
        $proxyMISPElements = [
            'attribute' => Hash::combine($event, 'Attribute.{n}.id', 'Attribute.{n}'),
            'object' => $objects,
            'objectTemplates' => $objectTemplates
        ];
        $this->set('proxyMISPElements', $proxyMISPElements);
        $this->set('id', $report_id);
        $this->set('report', $report);
        $this->set('ajax', $ajax);
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
    }

    public function viewSummary($report_id)
    {
        $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $report_id)));
        if (empty($report)) {
            throw new NotFoundException(__('Invalid Event Report'));
        }
        $report = $report[0];
        $event = $this->EventReport->Event->fetchEvent($this->Auth->user(), ['eventid' => $report['EventReport']['event_id']]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event'));
        }
        $event = $event[0];
        $proxyMISPElements = [
            'attribute' => Hash::combine($event, 'Attribute.{n}.id', 'Attribute.{n}'),
            'object' => Hash::combine($event, 'Object.{n}.id', 'Object.{n}'),
        ];
        $this->set('proxyMISPElements', $proxyMISPElements);
        $this->set('id', $report_id);
        $this->set('report', $report);
        $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
        $this->set('distributionLevels', $distributionLevels);
    }

    public function edit($id)
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $report = $this->request->data;
            if (!isset($report['EventReport'])) {
                $report = array('EventReport' => $report);
            }
            $report['EventReport']['id'] = $id;
            $errors = $this->EventReport->editReport($this->Auth->user(), $report);
            if (!empty($errors)) {
                $flashErrorMessage = implode(', ', $errors);
                $this->Flash->error($flashErrorMessage);
            } else {
                $this->redirect(array('controller' => 'eventReports', 'action' => 'view', $id));
            }
        } else {
            $report = $this->EventReport->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=true);
            $this->request->data = $report;
        }

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

    public function delete($id)
    {
        $report = $this->EventReport->fetchReports($this->Auth->user(), array('conditions' => array('id' => $id)));
        if (empty($report)) {
            throw new NotFoundException(__('Invalid Event Report'));
        }
        $this->EventReport->delete($id);
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
            $filters['context'] = 'all';
        } elseif ($filters['context'] == 'deleted') {
            $contextConditions['EventReport.deleted'] = true;
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
            $reports = $this->EventReports->find('all', 
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($eventConditions, $searchConditions, $aclConditions, $contextConditions)
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
            $distributionLevels = $this->EventReport->Event->Attribute->distributionLevels;
            $this->set('distributionLevels', $distributionLevels);
        }
    }

}
