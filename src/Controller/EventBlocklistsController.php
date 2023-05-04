<?php

namespace App\Controller;

use App\Controller\AppController;

class EventBlocklistsController extends AppController
{
    public $quickFilterFields = ['event_uuid', 'comment', 'event_info', 'event_orgc'];
    public $filterFields = ['event_uuid', 'comment', 'event_info', 'event_orgc'];

    public function initialize(): void
    {
        parent::initialize();
        $this->loadComponent('BlockList', [
            'controller' => $this,
            'table' => $this->modelClass,
        ]);
    }

    public function index()
    {
        $this->CRUD->index([
            'filters' => $this->filterFields,
            'quickFilters' => $this->quickFilterFields
        ]);

        $responsePayload = $this->CRUD->getResponsePayload();

        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function add()
    {
        return $this->BlockList->add($this->ParamHandler->isRest());
    }

    public function edit($id)
    {
        return $this->BlockList->edit($id, $this->ParamHandler->isRest());
    }

    public function delete($id)
    {
        return $this->BlockList->delete($id, $this->ParamHandler->isRest());
    }

    public function massDelete()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['EventBlocklist'])) {
                $this->request->data = array('EventBlocklist' => $this->request->data);
            }
            $ids = $this->request->data['EventBlocklist']['ids'];
            $event_ids = json_decode($ids, true);
            if (empty($event_ids)) {
                throw new NotFoundException(__('Invalid event IDs.'));
            }
            $result = $this->EventBlocklist->deleteAll(array('EventBlocklist.id' => $event_ids));
            if ($result) {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('EventBlocklist', 'Deleted', $ids, $this->response->type());
                } else {
                    $this->Flash->success('Blocklist entry removed');
                    $this->redirect(array('controller' => 'eventBlocklists', 'action' => 'index'));
                }
            } else {
                $error = __('Failed to delete Event from EventBlocklist. Error: ') . PHP_EOL . h($result);
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('EventBlocklist', 'Deleted', false, $error, $this->response->type());
                } else {
                    $this->Flash->error($error);
                    $this->redirect(array('controller' => 'eventBlocklists', 'action' => 'index'));
                }
            }
        } else {
            $ids = json_decode($this->request->query('ids'), true);
            if (empty($ids)) {
                throw new NotFoundException(__('Invalid event blocklist IDs.'));
            }
            $this->set('event_ids', $ids);
        }
    }
}
