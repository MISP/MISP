<?php
App::uses('AppController', 'Controller');

/**
 * @property Regexp $Regexp
 * @property AdminCrudComponent $AdminCrud
 */
class RegexpController extends AppController
{
    public $components = array('RequestHandler', 'AdminCrud');

    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'Regexp.id' => 'ASC'
        )
    );

    public function admin_add()
    {
        $this->loadModel('MispAttribute');
        $types = array_keys($this->MispAttribute->typeDefinitions);
        if ($this->request->is('post')) {
            if ($this->request->data['Regexp']['all'] == 1) {
                $this->Regexp->create();
                if ($this->Regexp->save($this->request->data)) {
                    $this->Flash->success(__('The Regexp has been saved.'));
                    $this->redirect(array('action' => 'index'));
                } else {
                    if (!($this->Session->check('Message.flash'))) {
                        $this->Flash->error(__('The Regexp could not be saved. Please, try again.'));
                    }
                }
            } else {
                $success = false;
                foreach ($types as $key => $type) {
                    if ($this->request->data['Regexp'][$key] == 1) {
                        $this->Regexp->create();
                        $this->request->data['Regexp']['type'] = $type;
                        $this->Regexp->save($this->request->data);
                        $success = true;
                    }
                }
                if ($success) {
                    $this->Flash->success(__('The Regular expressions have been saved.'));
                    $this->redirect(array('action' => 'index'));
                } else {
                    $this->Flash->error(__('Could not create the Regex entry as no types were selected. Either check "All" or check the types that you wish the Regex to affect.'));
                }
            }
        }
        $this->set('types', $types);
    }

    public function admin_index()
    {
        $this->AdminCrud->adminIndex();
    }

    public function admin_edit($id = null)
    {
        // unlike other edits, the new regexp edit will actually create copies of an entry and delete the old ones. The reason for this is that each regular expression can now
        // have several entries for different types. For example, /127.0.0.1/ -> '' can be an entry for ip-src, ip-dst, but not url, meaning that the string 127.0.0.1 would be blocked
        // for ip-src and ip-dst attribute entry, but not for url.
        $this->loadModel('MispAttribute');
        $types = array_keys($this->MispAttribute->typeDefinitions);
        $this->Regexp->id = $id;
        if (!$this->Regexp->exists()) {
            throw new NotFoundException('Invalid Regexp');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            unset($this->request->data['Regexp']['id']);
            // If 'all' is set, it overrides all other type settings. Create an attribute with the "all" setting and save it. Also, delete the original(s)
            if ($this->request->data['Regexp']['all'] == 1) {
                $this->Regexp->create();
                $this->request->data['Regexp']['type'] = 'ALL';
                if ($this->Regexp->save($this->request->data)) {
                    $this->Regexp->find_similar($id, true);
                    $this->Flash->success('The Regexp has been saved');
                    $this->redirect(array('action' => 'index'));
                } else {
                    if (!($this->Session->check('Message.flash'))) {
                        $this->Flash->error('The Regexp could not be saved. Please, try again.');
                    }
                }
            } else {
                // Keep track of which types could not be entered
                $failcount = 0;
                $oldArray = $this->Regexp->find_similar($id);
                $success = false;
                foreach ($types as $key => $type) {
                    // If the checkbox for this type was ticked, create an entry for it
                    if ($this->request->data['Regexp'][$key] == 1) {
                        $this->Regexp->create();
                        $this->request->data['Regexp']['type'] = $type;
                        $success = true;
                        // Add to the failcount if the save fails. Ideally this should be 0
                        if (!$this->Regexp->save($this->request->data)) {
                            $failcount++;
                        }
                    }
                }
                if ($success) {
                    if ($failcount == 0) {
                        // we have managed to successfully save all of the new attributes, time to run through the array containing all of the old entries and delete them.
                        foreach ($oldArray as $old) {
                            $this->Regexp->delete($old[0]);
                        }
                        $this->Flash->success(__('The Regular expressions have been saved.'));
                        $this->redirect(array('action' => 'index'));
                    } else {
                        // Since some insertions failed, don't delete the old entries. It's an edit that failed after all
                        $this->Flash->error('There were issues saving all of the regexp entries, therefore the old entries were not deleted.');
                    }
                } else {
                    $this->Flash->error(__('Could not create the Regex entry as no types were selected. Either check "All" or check the types that you wish the Regex to affect.'));
                    foreach ($this->request->data['Regexp'] as $k => $t) {
                        if (is_numeric($k)) {
                            $values[$k] = ($t == '1') ? true : false;
                        }
                    }
                    $this->set('all', $this->request->data['Regexp']['all'] == '1' ? true:false);
                    $this->set('value', $values);
                }
            }
        } else {
            // Show the user the regular expression entry that he/she is trying to edit, but also find all of the similar entries and mark the checkboxes appropriately
            // Similar meaning entries with the same 'regexp' and 'replacement' fields but different types
            $this->request->data['Regexp']['id'] = $id;
            $this->request->data = $this->Regexp->read(null, $id);
            $similarArray = $this->Regexp->find_similar($id);
            $values = array();
            // all is set separately from the other check-boxes
            if ($this->request->data['Regexp']['type'] === 'ALL') {
                $this->set('all', true);
            } else {
                $this->set('all', false);
            }
            // set the checkboxes for each type
            foreach ($types as $key => $type) {
                $values[$key] = false;
                foreach ($similarArray as $similar) {
                    if ($type === $similar[1]) {
                        $values[$key] = true;
                    }
                }
            }
            $this->set('value', $values);
        }
        $this->set('types', $types);
    }

    public function admin_delete($id = null)
    {
        $this->AdminCrud->adminDelete($id);
    }

    public function index()
    {
        $this->recursive = 0;
        $this->set('list', $this->paginate());
    }

    public function admin_clean()
    {
        $this->request->allowMethod(['post']);

        $allRegexp = $this->Regexp->find('all');
        $deletable = array();
        $modifications = 0;
        $this->loadModel('MispAttribute');
        $count = $this->MispAttribute->find('count', array());
        $chunks = ceil($count / 1000);
        for ($i = 1; $i <= $chunks; $i++) {
            $all = $this->MispAttribute->find('all', array(
                'recursive' => -1,
                'deleted' => 0,
                'limit' => 1000,
                'page' => $i
            ));
            foreach ($all as $item) {
                $result = $this->Regexp->replaceSpecific($item['Attribute']['value'], $allRegexp, $item['Attribute']['type']);
                // 0 = delete it, it is a blocked regexp; 1 = ran regexp check, made changes, resave this attribute with the new value; 2 = ran regexp check, no changes made, go on
                if ($result == 0) {
                    $deletable[] = $item['Attribute']['id'];
                } else {
                    // Until now this wasn't checked and all attributes were resaved, no matter if they were changed...
                    if ($result == 1) {
                        $this->MispAttribute->save($item);
                        $modifications++;
                    }
                }
            }
        }
        if (count($deletable)) {
            foreach ($deletable as $item) {
                $this->MispAttribute->delete($item);
            }
        }
        $this->Flash->info(__('All done! Number of changed attributes: ' . $modifications . ' Number of deletions: ' . count($deletable)));
        $this->redirect(array('action' => 'index'));
    }


    public function cleanRegexModifiers()
    {
        $this->request->allowMethod(['post']);

        $entries = $this->Regexp->find('all', array());
        $changes = 0;
        foreach ($entries as $entry) {
            $length = strlen($entry['Regexp']['regexp']);
            $this->Regexp->sanitizeModifiers($entry['Regexp']['regexp']);
            if (strlen($entry['Regexp']['regexp']) < $length) {
                $this->Regexp->save($entry);
                $changes++;
            }
        }
        $this->Flash->info(__('All done! Found and cleaned ' . $changes . ' potentially malcious regexes.'));
        $this->redirect('/pages/display/administration');
    }
}
