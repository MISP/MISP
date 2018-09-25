<?php
App::uses('AppController', 'Controller');

class WarninglistsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'contain' => array(
                'WarninglistType'
            ),
            'order' => array(
                'Warninglist.id' => 'DESC'
            ),
    );

    public function index()
    {
        $this->paginate['recursive'] = -1;
        $warninglists = $this->paginate();
        foreach ($warninglists as &$warninglist) {
            $warninglist['Warninglist']['valid_attributes'] = array();
            foreach ($warninglist['WarninglistType'] as $type) {
                $warninglist['Warninglist']['valid_attributes'][] = $type['type'];
            }
            $warninglist['Warninglist']['valid_attributes'] = implode(', ', $warninglist['Warninglist']['valid_attributes']);
            unset($warninglist['WarninglistType']);
        }
        if ($this->_isRest()) {
            $this->set('Warninglists', $warninglists);
            $this->set('_serialize', array('Warninglists'));
        } else {
            $this->set('warninglists', $warninglists);
        }
    }

    public function update()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This action is only accessible via POST requests.');
        }
        $result = $this->Warninglist->update();
        $this->Log = ClassRegistry::init('Log');
        $fails = 0;
        $successes = 0;
        if (!empty($result)) {
            if (isset($result['success'])) {
                foreach ($result['success'] as $id => $success) {
                    if (isset($success['old'])) {
                        $change = $success['name'] . ': updated from v' . $success['old'] . ' to v' . $success['new'];
                    } else {
                        $change = $success['name'] . ' v' . $success['new'] . ' installed';
                    }
                    $this->Log->create();
                    $this->Log->save(array(
                            'org' => $this->Auth->user('Organisation')['name'],
                            'model' => 'Warninglist',
                            'model_id' => $id,
                            'email' => $this->Auth->user('email'),
                            'action' => 'update',
                            'user_id' => $this->Auth->user('id'),
                            'title' => 'Warning list updated',
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
                            'model' => 'Warninglist',
                            'model_id' => $id,
                            'email' => $this->Auth->user('email'),
                            'action' => 'update',
                            'user_id' => $this->Auth->user('id'),
                            'title' => 'Warning list failed to update',
                            'change' => $fail['name'] . ' could not be installed/updated. Error: ' . $fail['fail'],
                    ));
                    $fails++;
                }
            }
        } else {
            $this->Log->create();
            $this->Log->save(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => 'Warninglist',
                    'model_id' => 0,
                    'email' => $this->Auth->user('email'),
                    'action' => 'update',
                    'user_id' => $this->Auth->user('id'),
                    'title' => 'Warninglist update (nothing to update)',
                    'change' => 'Executed an update of the warning lists, but there was nothing to update.',
            ));
        }
        if ($successes == 0 && $fails == 0) {
            $flashType = 'info';
            $message = 'All warninglists are up to date already.';
        } elseif ($successes == 0) {
            $flashType = 'error';
            $message = 'Could not update any of the warning lists';
        } else {
            $flashType = 'success';
            $message = 'Successfully updated ' . $successes . ' warninglists.';
            if ($fails != 0) {
                $message . ' However, could not update ' . $fails . ' warning list.';
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Warninglist', 'update', false, $this->response->type(), $message);
        } else {
            $this->Flash->{$flashType}($message);
            $this->redirect(array('controller' => 'warninglists', 'action' => 'index'));
        }
    }

	/*
	 * toggle warninglists on or offset
	 * Simply POST an ID or a list of IDs to toggle the current state
	 * To control what state the warninglists should have after execution instead of just blindly toggling them, simply pass the enabled flag
	 * Example:
	 *   {"id": [5, 8], "enabled": 1}
     * Alternatively search by a substring in the warninglist's named, such as:
     *   {"name": ["%alexa%", "%iana%"], "enabled": 1}
	 */
    public function toggleEnable()
    {
		if (!$this->request->is('post')) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'This function only accepts POST requests.')), 'status' => 200, 'type' => 'json'));
		}
		if (isset($this->request->data['Warninglist']['data'])) {
			$id = $this->request->data['Warninglist']['data'];
		} else {
			if (!empty($this->request->data['id'])) {
				$id = $this->request->data['id'];
			} else if (!empty($this->request->data['name'])) {
				if (!is_array($this->request->data['name'])) {
					$names = array($this->request->data['name']);
				} else {
					$names = $this->request->data['name'];
				}
				$conditions = array();
				foreach ($names as $k => $name) {
					$conditions['OR'][] = array('LOWER(Warninglist.name) LIKE' => strtolower($name));
				}
				$id = $this->Warninglist->find('list', array(
					'conditions' => $conditions,
					'recursive' => -1,
					'fields' => array('Warninglist.id', 'Warninglist.id')
				));
			}
		}
		if (isset($this->request->data['enabled'])) {
			$enabled = $this->request->data['enabled'];
		}
        if (empty($id)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist not found.')), 'status' => 200, 'type' => 'json'));
        }
        $currentState = $this->Warninglist->find('all', array('conditions' => array('id' => $id), 'recursive' => -1));
        if (empty($currentState)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist(s) not found.')), 'status' => 200, 'type' => 'json'));
        }
		$success = 0;
		foreach ($currentState as $warningList) {
			if (isset($enabled)) {
				$warningList['Warninglist']['enabled'] = $enabled;
				$message = $enabled ? 'enabled' : 'disabled';
			} else {
		        if ($warningList['Warninglist']['enabled']) {
		            $warningList['Warninglist']['enabled'] = 0;
		            $message = 'disabled';
		        } else {
		            $warningList['Warninglist']['enabled'] = 1;
		            $message = 'enabled';
		        }
				if (!isset($enabled) && count($currentState) > 1) {
					$message = 'toggled';
				}
			}
			if ($this->Warninglist->save($warningList)) {
				$success += 1;
			}
			$this->Warninglist->regenerateWarninglistCaches($warningList['Warninglist']['id']);
		}
        if ($success) {
            $this->Warninglist->regenerateWarninglistCaches($id);
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $success . ' warninglist(s) ' . $message)), 'status' => 200, 'type' => 'json'));
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Warninglist(s) could not be toggled.')), 'status' => 200, 'type' => 'json'));
        }
    }

    public function enableWarninglist($id, $enable = false)
    {
        $this->Warninglist->id = $id;
        if (!$this->Warninglist->exists()) {
            throw new NotFoundException('Invalid Warninglist.');
        }
        // DBMS interoperability: convert boolean false to integer 0 so cakephp doesn't try to insert an empty string into the database
        if ($enable === false) {
            $enable = 0;
        }
        $this->Warninglist->saveField('enabled', $enable);
        $this->Warninglist->regenerateWarninglistCaches($id);
        $this->Flash->success('Warninglist enabled');
        $this->redirect(array('controller' => 'warninglists', 'action' => 'view', $id));
    }

    public function getToggleField()
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is available via AJAX only.');
        }
        $this->layout = 'ajax';
        $this->render('ajax/getToggleField');
    }

    public function view($id)
    {
        if (!is_numeric($id)) {
            throw new NotFoundException('Invalid ID.');
        }
        $warninglist = $this->Warninglist->find('first', array('contain' => array('WarninglistEntry', 'WarninglistType'), 'conditions' => array('id' => $id)));
        if (empty($warninglist)) {
            throw new NotFoundException('Warninglist not found.');
        }
        if ($this->_isRest()) {
            $warninglist['Warninglist']['WarninglistEntry'] = $warninglist['WarninglistEntry'];
            $warninglist['Warninglist']['WarninglistType'] = $warninglist['WarninglistType'];
            $this->set('Warninglist', $warninglist['Warninglist']);
            $this->set('_serialize', array('Warninglist'));
        } else {
            $this->set('warninglist', $warninglist);
        }
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $id = intval($id);
            $result = $this->Warninglist->quickDelete($id);
            if ($result) {
                $this->Flash->success('Warninglist successfuly deleted.');
                $this->redirect(array('controller' => 'warninglists', 'action' => 'index'));
            } else {
                $this->Flash->error('Warninglists could not be deleted.');
                $this->redirect(array('controller' => 'warninglists', 'action' => 'index'));
            }
        } else {
            if ($this->request->is('ajax')) {
                $this->set('id', $id);
                $this->render('ajax/delete_confirmation');
            } else {
                throw new MethodNotAllowedException('This function can only be reached via AJAX.');
            }
        }
    }
}
