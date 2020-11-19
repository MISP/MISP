<?php
App::uses('AppController', 'Controller');

class GalaxyClusterBlocklistsController extends AppController
{
    public $components = array('Session', 'RequestHandler', 'BlockList');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 clusters <- no we won't, this is the max a user van view/page.
            'order' => array(
                'GalaxyClusterBlocklist.created' => 'DESC'
            ),
    );

    public function index()
    {
        $passedArgsArray = array();
        $passedArgs = $this->passedArgs;
        $params = array();
        $validParams = array('cluster_uuid', 'comment', 'cluster_info', 'cluster_orgc');
        foreach ($validParams as $validParam) {
            if (!empty($this->params['named'][$validParam])) {
                $params[$validParam] = $this->params['named'][$validParam];
            }
        }
        if (!empty($this->params['named']['searchall'])) {
            $params['AND']['OR'] = array(
                'cluster_uuid' => $this->params['named']['searchall'],
                'comment' => $this->params['named']['searchall'],
                'cluster_info' => $this->params['named']['searchall'],
                'cluster_orgc' => $this->params['named']['searchall']
            );
        }
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgsArray);
        return $this->BlockList->index($this->_isRest(), $params);
    }

    public function add()
    {
        $this->set('action', 'add');
        return $this->BlockList->add($this->_isRest());
    }

    public function edit($id)
    {
        $this->set('action', 'edit');
        return $this->BlockList->edit($this->_isRest(), $id);
    }

    public function delete($id)
    {
        if (Validation::uuid($id)) {
            $entry = $this->GalaxyClusterBlocklist->find('first', array(
                'conditions' => array('cluster_uuid' => $id)
            ));
            if (empty($entry)) {
                throw new NotFoundException(__('Invalid blocklist entry'));
            }
            $id = $entry['GalaxyClusterBlocklist']['id'];
        }
        return $this->BlockList->delete($this->_isRest(), $id);
    }

    public function massDelete()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['GalaxyClusterBlocklist'])) {
                $this->request->data = array('GalaxyClusterBlocklist' => $this->request->data);
            }
            $ids = $this->request->data['GalaxyClusterBlocklist']['ids'];
            $cluster_ids = json_decode($ids, true);
            if (empty($cluster_ids)) {
                throw new NotFoundException(__('Invalid cluster IDs.'));
            }
            $result = $this->GalaxyClusterBlocklist->deleteAll(array('GalaxyClusterBlocklist.id' => $cluster_ids));
            if ($result) {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterBlocklist', 'Deleted', $ids, $this->response->type());
                } else {
                    $this->Flash->success('Blocklist entry removed');
                    $this->redirect(array('controller' => 'GalaxyClusterBlocklist', 'action' => 'index'));
                }
            } else {
                $error = __('Failed to delete GalaxyCluster from GalaxyClusterBlocklist. Error: ') . PHP_EOL . h($result);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterBlocklist', 'Deleted', false, $error, $this->response->type());
                } else {
                    $this->Flash->error($error);
                    $this->redirect(array('controller' => 'galaxyClusterBlocklists', 'action' => 'index'));
                }
            }
        } else {
            $ids = json_decode($this->request->query('ids'), true);
            if (empty($ids)) {
                throw new NotFoundException(__('Invalid cluster IDs.'));

            }
            $this->set('cluster_ids', $ids);
        }
    }
}
