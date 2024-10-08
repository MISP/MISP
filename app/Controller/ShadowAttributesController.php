<?php
App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('AttachmentTool', 'Tools');

/**
 * @property ShadowAttribute $ShadowAttribute
 */
class ShadowAttributesController extends AppController
{
    public $components = array('RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,
        );

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->set('title_for_layout', 'Proposals');

        // convert uuid to id if present in the url, and overwrite id field
        if (isset($this->params->query['uuid'])) {
            $params = array(
                'conditions' => array('ShadowAttribute.uuid' => $this->params->query['uuid']),
                'recursive' => 0,
                'fields' => 'ShadowAttribute.id'
            );
            $result = $this->ShadowAttribute->find('first', $params);
            if (isset($result['ShadowAttribute']) && isset($result['ShadowAttribute']['id'])) {
                $id = $result['ShadowAttribute']['id'];
                $this->params->addParams(array('pass' => array($id))); // FIXME find better way to change id variable if uuid is found. params->url and params->here is not modified accordingly now
            }
        }
    }

    private function __accept($id)
    {
        $this->loadModel('MispAttribute');
        $this->MispAttribute->Behaviors->detach('SysLogLogable.SysLogLogable');
        $shadow = $this->ShadowAttribute->find(
            'first',
            array(
                'recursive' => -1,
                'conditions' => array(
                    'ShadowAttribute.id' => $id,
                    'deleted' => 0
                ),
            )
        );
        if (empty($shadow)) {
            return array('false' => true, 'errors' => 'Proposal not found or you are not authorised to accept it.');
        }
        $shadow = $shadow['ShadowAttribute'];

        $this->loadModel('Event');
        $event = $this->Event->read(null, $shadow['event_id']);
        if (!$this->_isRest()) {
            $this->Event->insertLock($this->Auth->user(), $event['Event']['id']);
        }

        // If the old_id is set to anything but 0 then we're dealing with a proposed edit to an existing attribute
        if ($shadow['old_id'] != 0) {
            // Find the live attribute by the shadow attribute's uuid, so we can begin editing it
            $activeAttribute = $this->MispAttribute->find('first', [
                'conditions' => ['Attribute.uuid' => $shadow['uuid']],
                'contain' => ['Event'],
            ]);

            // Send those away that shouldn't be able to edit this
            if (!$this->__canModifyEvent($activeAttribute)) {
                if ($this->_isRest()) {
                    return ['false' => true, 'errors' => 'Proposal not found or you are not authorised to accept it.'];
                } else {
                    $this->Flash->error('You don\'t have permission to do that');
                    $this->redirect(['controller' => 'events', 'action' => 'view', $shadow['event_id']]);
                }
            }
        } else {
            if (!$this->__canModifyEvent($event)) {
                $this->Flash->error('You don\'t have permission to do that');
                $this->redirect(array('controller' => 'events', 'action' => 'index'));
            }
        }
        $result = $this->ShadowAttribute->acceptProposal($this->Auth->user(), ['ShadowAttribute' => $shadow]);
        if ($result['success']) {
            return ['saved' => true, 'success' => $result['message']];
        } else {
            return ['false' => true, 'errors' => $result['message']];
        }
    }

    // Accept a proposed edit and update the attribute
    public function accept($id = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $response = $this->__accept($id);
        if ($this->_isRest()) {
            if (isset($response['success'])) {
                $response['check_publish'] = true;
                $this->set('name', $response['success']);
                $this->set('message', $response['success']);
                $this->set('url', $this->baseurl . '/shadow_attributes/accept/' . $id);
                $this->set('_serialize', array('name', 'message', 'url'));
            } else {
                throw new MethodNotAllowedException($response['errors']);
            }
        } else {
            $this->autoRender = false;
            return new CakeResponse(array('body'=> json_encode($response), 'status'=>200, 'type' => 'json'));
        }
    }

    private function __discard($id)
    {
        $sa = $this->ShadowAttribute->find(
                'first',
                array(
                    'recursive' => -1,
                    'contain' => 'Event',
                    'conditions' => array(
                        'ShadowAttribute.id' => $id,
                        'deleted' => 0
                    ),
                )
            );
        if (empty($sa)) {
            return false;
        }
        // Just auth of proposal or user that can edit event can discard proposal.
        if (!$this->__canModifyEvent($sa) && $this->Auth->user('email') !== $sa['ShadowAttribute']['email']) {
            return false;
        }
        return $this->ShadowAttribute->discardProposal($this->Auth->user(), $sa);
    }

    // This method will discard a proposed change. Users that can delete the proposals are the publishing users of the org that created the event and of the ones that created the proposal - in addition to site admins of course
    public function discard($id = null)
    {
        if ($this->request->is('post')) {
            if ($this->__discard($id)) {
                if ($this->_isRest()) {
                    $this->set('name', 'Proposal discarded.');
                    $this->set('message', 'Proposal discarded.');
                    $this->set('url', $this->baseurl . '/shadow_attributes/discard/' . $id);
                    $this->set('_serialize', array('name', 'message', 'url'));
                } else {
                    $this->autoRender = false;
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Proposal discarded.')), 'status'=>200, 'type' => 'json'));
                }
            } else {
                if ($this->_isRest()) {
                    throw new InternalErrorException(__('Could not discard proposal.'));
                } else {
                    $this->autoRender = false;
                    return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Could not discard proposal.')), 'status'=>200, 'type' => 'json'));
                }
            }
        } else {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException();
            }
            $this->autoRender = false;
            $this->set('id', $id);
            $shadowAttribute = $this->ShadowAttribute->find('first', array(
                    'conditions' => array('id' => $id),
                    'recursive' => -1,
                    'fields' => array('id', 'event_id'),
            ));
            $this->set('event_id', $shadowAttribute['ShadowAttribute']['event_id']);
            $this->render('ajax/shadowAttributeConfirmationForm');
        }
    }

    public function add($eventId)
    {
        if ($this->request->is('ajax')) {
            $this->set('ajax', true);
            $this->layout = false;
        } else {
            $this->set('ajax', false);
        }
        $event = $this->ShadowAttribute->Event->fetchSimpleEvent($this->Auth->user(), $eventId);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event'));
        }

        if ($this->request->is('post')) {
            if (isset($this->request->data['request'])) {
                $this->request->data = $this->request->data['request'];
            }
            // rearrange the request in case someone didn't RTFM
            $invalidNames = array('Attribute', 'Proposal');
            foreach ($invalidNames as $iN) {
                if (isset($this->request->data[$iN]) && !isset($this->request->data['ShadowAttribute'])) {
                    $this->request->data['ShadowAttribute'] = $this->request->data[$iN];
                }
            }
            if (!isset($this->request->data['ShadowAttribute'])) {
                $this->request->data = array('ShadowAttribute' => $this->request->data);
            }
            if ($this->request->is('ajax')) {
                $this->autoRender = false;
            }
            // Give error if someone tried to submit an attribute with type 'attachment' or 'malware-sample'.
            // TODO change behavior attachment options - this is bad ... it should rather by a messagebox or should be filtered out on the view level
            if (isset($this->request->data['ShadowAttribute']['type']) && $this->ShadowAttribute->typeIsAttachment($this->request->data['ShadowAttribute']['type']) && !$this->_isRest()) {
                $this->Flash->error(__('Attribute has not been added: attachments are added by "Add attachment" button', true), 'default', array(), 'error');
                $this->redirect(array('controller' => 'events', 'action' => 'view', $event['Event']['id']));
            }
            $this->request->data['ShadowAttribute']['event_id'] = $event['Event']['id'];
            //
            // multiple attributes in batch import
            //
            if (!$this->_isRest() && (isset($this->request->data['ShadowAttribute']['batch_import']) && $this->request->data['ShadowAttribute']['batch_import'] == 1)) {
                // make array from value field
                $attributes = explode("\n", $this->request->data['ShadowAttribute']['value']);
                $fails = "";    // will be used to keep a list of the lines that failed or succeeded
                $successes = "";
                // TODO loopholes
                // the value null value thing
                foreach ($attributes as $key => $attribute) {
                    $attribute = trim($attribute);
                    if (strlen($attribute) == 0) {
                        continue;
                    } // don't do anything for empty lines
                    $this->ShadowAttribute->create();
                    $this->request->data['ShadowAttribute']['value'] = $attribute; // set the value as the content of the single line
                    $this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
                    $this->request->data['ShadowAttribute']['org_id'] = $this->Auth->user('org_id');
                    $this->request->data['ShadowAttribute']['event_uuid'] = $event['Event']['uuid'];
                    $this->request->data['ShadowAttribute']['event_org_id'] = $event['Event']['org_id'];
                    // TODO loopholes
                    // there seems to be a loophole in MISP here
                    // be it an create and not an update
                    $this->ShadowAttribute->id = null;
                    if ($this->ShadowAttribute->save($this->request->data)) {
                        $successes .= " " . ($key + 1);
                    } else {
                        $fails .= " " . ($key + 1);
                    }
                }
                // we added all the attributes
                if ($this->request->is('ajax')) {
                    // handle it if some of them failed!
                    if ($fails) {
                        $error_message = 'The lines' . $fails . ' could not be saved. Please, try again.';
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $error_message)), 'status' => 200, 'type' => 'json'));
                    } else {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status' => 200, 'type' => 'json'));
                    }
                } else {
                    if ($fails) {
                        // list the ones that failed
                        if (!CakeSession::read('Message.flash')) {
                            $this->Flash->error(__('The lines' . $fails . ' could not be saved. Please, try again.', true));
                        } else {
                            $existingFlash = CakeSession::read('Message.flash');
                            $this->Flash->error(__('The lines' . $fails . ' could not be saved. ' . $existingFlash['message'], true));
                        }
                    }
                    if ($successes) {
                        // list the ones that succeeded
                        $emailResult = "";
                        if (!$this->ShadowAttribute->sendProposalAlertEmail($event['Event']['id']) === false) {
                            $emailResult = " but nobody from the owner organisation could be notified by e-mail.";
                        }
                        $this->Flash->success(__('The lines' . $successes . ' have been saved' . $emailResult, true));
                    }
                }

                $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
            } else {
                //
                // single attribute
                //
                // create the attribute
                $this->ShadowAttribute->create();
                $this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
                $this->request->data['ShadowAttribute']['org_id'] = $this->Auth->user('org_id');
                $this->request->data['ShadowAttribute']['event_uuid'] = $event['Event']['uuid'];
                $this->request->data['ShadowAttribute']['event_org_id'] = $event['Event']['org_id'];
                if ($this->ShadowAttribute->save($this->request->data)) {
                    // list the ones that succeeded
                    $emailResult = "";
                    if (!isset($this->request->data['ShadowAttribute']['deleted']) || !$this->request->data['ShadowAttribute']['deleted']) {
                        if (!$this->ShadowAttribute->sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id'])) {
                            $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
                        }
                    }
                    // inform the user and redirect
                    if ($this->request->is('ajax')) {
                        $this->autoRender = false;
                        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Proposal added' . $emailResult)), 'status'=>200, 'type' => 'json'));
                    } elseif ($this->_isRest()) {
                        $sa = $this->ShadowAttribute->find(
                            'first',
                            array(
                                'conditions' => array('ShadowAttribute.id' => $this->ShadowAttribute->id),
                                'recursive' => -1,
                                'fields' => array('id', 'old_id', 'event_id', 'type', 'category', 'value', 'comment','to_ids', 'uuid', 'event_org_id', 'email', 'deleted', 'timestamp', 'first_seen', 'last_seen')
                            )
                        );
                        $this->set('ShadowAttribute', $sa['ShadowAttribute']);
                        $this->set('_serialize', array('ShadowAttribute'));
                    } else {
                        $this->Flash->success(__('The proposal has been saved'));
                        $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
                    }
                } else {
                    if ($this->request->is('ajax')) {
                        $this->autoRender = false;
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $this->ShadowAttribute->validationErrors)), 'status'=>200, 'type' => 'json'));
                    } elseif ($this->_isRest()) {
                        $message = '';
                        foreach ($this->ShadowAttribute->validationErrors as $k => $v) {
                            $message .= '[' . $k . ']: ' . $v[0] . PHP_EOL;
                        }
                        throw new NotFoundException(__('Could not save the proposal. Errors: %s', $message));
                    } else {
                        $this->Flash->error(__('The proposal could not be saved. Please, try again.'));
                    }
                }
            }
        } else {
            // set the event_id in the form
            $this->request->data['ShadowAttribute']['event_id'] = $event['Event']['id'];
        }
        $this->set('event_id', $event['Event']['id']);
        $this->set('event', $event);
        // combobox for types
        $types = $this->ShadowAttribute->Attribute->getNonAttachmentTypes();
        $types = $this->_arrayToValuesIndexArray($types);
        $this->set('types', $types);
        // combobox for categories
        $categories = array_keys($this->ShadowAttribute->Attribute->categoryDefinitions);
        $categories = $this->_arrayToValuesIndexArray($categories);
        $this->set('categories', $categories);
        $this->__common();
        $this->set('categoryDefinitions', $this->ShadowAttribute->categoryDefinitions);
    }

    public function download($id)
    {
        $conditions = $this->ShadowAttribute->buildConditions($this->Auth->user());
        $conditions['ShadowAttribute.id'] = $id;
        $conditions['ShadowAttribute.deleted'] = 0;

        $sa = $this->ShadowAttribute->find('first', array(
            'recursive' => -1,
            'contain' => ['Event', 'Attribute'], // required because of conditions
            'conditions' => $conditions,
        ));
        if (!$sa) {
            throw new NotFoundException(__('Invalid Proposal'));
        }
        $this->__downloadAttachment($sa['ShadowAttribute']);
    }

    private function __downloadAttachment(array $shadowAttribute)
    {
        $file = $this->ShadowAttribute->getAttachmentFile($shadowAttribute);

        if ('attachment' === $shadowAttribute['type']) {
            $filename = $shadowAttribute['value'];
            $fileExt = pathinfo($filename, PATHINFO_EXTENSION);
            $filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
        } elseif ('malware-sample' === $shadowAttribute['type']) {
            $filenameHash = explode('|', $shadowAttribute['value']);
            $filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
            $fileExt = "zip";
        } else {
            throw new NotFoundException(__('Proposal not an attachment or malware-sample'));
        }
        $this->autoRender = false;
        $this->response->type($fileExt);
        $this->response->file($file->path, array('download' => true, 'name' => $filename . '.' . $fileExt));
    }

    public function add_attachment($eventId = null)
    {
        $event = $this->ShadowAttribute->Event->fetchSimpleEvent($this->Auth->user(), $eventId);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event'));
        }
        if ($this->request->is('post')) {
            // Check if there were problems with the file upload
            // only keep the last part of the filename, this should prevent directory attacks
            $hashes = array('md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256');
            $filename = basename($this->request->data['ShadowAttribute']['value']['name']);
            $tmpfile = new File($this->request->data['ShadowAttribute']['value']['tmp_name']);
            if ((isset($this->request->data['ShadowAttribute']['value']['error']) && $this->request->data['ShadowAttribute']['value']['error'] == 0) ||
            (!empty($this->request->data['ShadowAttribute']['value']['tmp_name']) && $this->request->data['ShadowAttribute']['value']['tmp_name'] != 'none')
            ) {
                if (!is_uploaded_file($tmpfile->path)) {
                    throw new InternalErrorException(__('PHP says file was not uploaded. Are you attacking me?'));
                }
            } else {
                $this->Flash->error(__('There was a problem to upload the file.'));
                $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
            }

            $fails = array();
            $completeFail = false;

            if ($this->request->data['ShadowAttribute']['malware']) {
                $result = $this->ShadowAttribute->Event->Attribute->handleMaliciousBase64($this->request->data['ShadowAttribute']['event_id'], $filename, base64_encode($tmpfile->read()), array_keys($hashes));
                if (!$result['success']) {
                    $this->Flash->error(__('There was a problem to upload the file.'), 'default', array(), 'error');
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
                }
                foreach ($hashes as $hash => $typeName) {
                    if (!$result[$hash]) {
                        continue;
                    }
                    $shadowAttribute = array(
                            'ShadowAttribute' => array(
                                    'value' => $filename . '|' . $result[$hash],
                                    'category' => $this->request->data['ShadowAttribute']['category'],
                                    'type' => $typeName,
                                    'event_id' => $this->request->data['ShadowAttribute']['event_id'],
                                    'comment' => $this->request->data['ShadowAttribute']['comment'],
                                    'to_ids' => 1,
                                    'email' => $this->Auth->user('email'),
                                    'org_id' => $this->Auth->user('org_id'),
                                    'event_uuid' => $event['Event']['uuid'],
                                    'event_org_id' => $event['Event']['orgc_id'],
                            )
                    );
                    if ($hash == 'md5') {
                        $shadowAttribute['ShadowAttribute']['data'] = $result['data'];
                    }
                    $this->ShadowAttribute->create();
                    $r = $this->ShadowAttribute->save($shadowAttribute);
                    if ($r == false) {
                        $fails[] = array($typeName);
                    }
                    if (count($fails) == count($hashes)) {
                        $completeFail = true;
                    }
                }
            } else {
                $shadowAttribute = array(
                    'ShadowAttribute' => array(
                        'value' => $filename,
                        'category' => $this->request->data['ShadowAttribute']['category'],
                        'type' => 'attachment',
                        'event_id' => $this->request->data['ShadowAttribute']['event_id'],
                        'comment' => $this->request->data['ShadowAttribute']['comment'],
                        'data' => base64_encode($tmpfile->read()),
                        'to_ids' => 0,
                        'email' => $this->Auth->user('email'),
                        'org_id' => $this->Auth->user('org_id'),
                        'event_uuid' => $event['Event']['uuid'],
                        'event_org_id' => $event['Event']['orgc_id'],
                    )
                );
                $this->ShadowAttribute->create();
                $r = $this->ShadowAttribute->save($shadowAttribute);
                if ($r == false) {
                    $fails[] = array('attachment');
                    $completeFail = true;
                }
            }
            if (!$completeFail) {
                if (empty($fails)) {
                    $this->Flash->success(__('The attachment has been uploaded'));
                } else {
                    $this->Flash->success(__('The attachment has been uploaded, but some of the proposals could not be created. The failed proposals are: ' . implode(', ', $fails)));
                }
            } else {
                $this->Flash->error(__('The attachment could not be saved, please contact your administrator.'));
            }
            $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
        } else {
            // set the event_id in the form
            $this->request->data['ShadowAttribute']['event_id'] = $event['Event']['id'];
        }

        // just get them with attachments..
        $selectedCategories = array();
        foreach ($this->ShadowAttribute->categoryDefinitions as $category => $values) {
            foreach ($values['types'] as $type) {
                if ($this->ShadowAttribute->typeIsAttachment($type)) {
                    $selectedCategories[] = $category;
                    break;
                }
            }
        }

        // Create list of categories that should be marked as malware sample by default
        $isMalwareSampleCategory = [];
        foreach ($selectedCategories as $category) {
            $possibleMalwareSample = false;
            foreach ($this->ShadowAttribute->categoryDefinitions[$category]['types'] as $type) {
                if ($this->ShadowAttribute->typeIsMalware($type)) {
                    $possibleMalwareSample = true;
                    break;
                }
            }
            $isMalwareSampleCategory[$category] = $possibleMalwareSample;
        }

        $categories = $this->_arrayToValuesIndexArray($selectedCategories);
        $this->set('categories', $categories);
        $this->__common();
        $this->set('attrDescriptions', $this->ShadowAttribute->fieldDescriptions);
        $this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
        $this->set('categoryDefinitions', $this->ShadowAttribute->categoryDefinitions);
        $this->set('isMalwareSampleCategory', $isMalwareSampleCategory);
        $this->set('mayModify', $this->__canModifyEvent($event));
        $this->set('event', $event);
        $this->set('title_for_layout', __('Propose attachment'));
    }

    // Propose an edit to an attribute
    // Fields that can be used to edit an attribute when using the API:
    // type, category, value, comment, to_ids
    // if any of these fields is set, it will create a proposal
    public function edit($id = null)
    {
        $existingAttribute = $this->ShadowAttribute->Attribute->fetchAttributes($this->Auth->user(), array(
            'contain' => ['Event' => ['fields' => ['Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.distribution', 'Event.uuid', 'Event.user_id']]],
            'conditions' => $this->__attributeIdToConditions($id),
            'flatten' => 1
        ));
        if (empty($existingAttribute)) {
            throw new NotFoundException(__('Invalid Attribute.'));
        }
        $existingAttribute = $existingAttribute[0];

        // Check if the attribute is an attachment, if yes, block the type and the value fields from being edited.
        if ($this->ShadowAttribute->Attribute->typeIsAttachment($existingAttribute['Attribute']['type'])) {
            $this->set('attachment', true);
            $attachment = true;
        } else {
            $this->set('attachment', false);
            $attachment = false;
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            if (isset($this->request->data['request'])) {
                $this->request->data = $this->request->data['request'];
            }
            if (!isset($this->request->data['ShadowAttribute'])) {
                $this->request->data['ShadowAttribute'] = $this->request->data;
            }
            // rearrange the request in case someone didn't RTFM
            $invalidNames = array('Attribute', 'Proposal');
            foreach ($invalidNames as $iN) {
                if (isset($this->request->data[$iN]) && !isset($this->request->data['ShadowAttribute'])) {
                    $this->request->data['ShadowAttribute'] = $this->request->data[$iN];
                }
            }
            if ($attachment) {
                $fields = array(
                    'static' => array('old_id' => 'Attribute.id', 'uuid' => 'Attribute.uuid', 'event_id' => 'Attribute.event_id', 'event_uuid' => 'Event.uuid', 'event_org_id' => 'Event.orgc_id', 'category' => 'Attribute.category', 'type' => 'Attribute.type'),
                    'optional' => array('value', 'to_ids', 'comment', 'first_seen', 'last_seen')
                );
            } else {
                $fields = array(
                    'static' => array('old_id' => 'Attribute.id', 'uuid' => 'Attribute.uuid', 'event_id' => 'Attribute.event_id', 'event_uuid' => 'Event.uuid', 'event_org_id' => 'Event.orgc_id'),
                    'optional' => array('category', 'type', 'value', 'to_ids', 'comment', 'first_seen', 'last_seen')
                );
                if ($existingAttribute['Attribute']['object_id']) {
                    unset($fields['optional']['type']);
                    $fields['static']['type'] = 'Attribute.type';
                }
            }
            foreach ($fields['static'] as $k => $v) {
                $v = explode('.', $v);
                $this->request->data['ShadowAttribute'][$k] = $existingAttribute[$v[0]][$v[1]];
            }
            $validChangeMade = false;
            foreach ($fields['optional'] as $v) {
                if (!isset($this->request->data['ShadowAttribute'][$v])) {
                    $this->request->data['ShadowAttribute'][$v] = $existingAttribute['Attribute'][$v];
                } else {
                    $validChangeMade = true;
                }
            }
            if (!$validChangeMade) {
                throw new MethodNotAllowedException(__('Invalid input.'));
            }
            $this->request->data['ShadowAttribute']['org_id'] =  $this->Auth->user('org_id');
            $this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
            if ($this->ShadowAttribute->save($this->request->data)) {
                $emailResult = "";
                if (!isset($this->request->data['ShadowAttribute']['deleted']) || !$this->request->data['ShadowAttribute']['deleted']) {
                    if (!$this->ShadowAttribute->sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id'])) {
                        $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
                    }
                }
                if ($this->_isRest()) {
                    $sa = $this->ShadowAttribute->find(
                            'first',
                            array(
                                'conditions' => array('ShadowAttribute.id' => $this->ShadowAttribute->id),
                                'recursive' => -1,
                                'fields' => array('id', 'old_id', 'event_id', 'type', 'category', 'value', 'comment','to_ids', 'uuid', 'event_org_id', 'email', 'deleted', 'timestamp', 'first_seen', 'last_seen')
                            )
                    );
                    $this->set('ShadowAttribute', $sa['ShadowAttribute']);
                    $this->set('_serialize', array('ShadowAttribute'));
                } else {
                    $this->Flash->success(__('The proposed Attribute has been saved' . $emailResult));
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $existingAttribute['Attribute']['event_id']));
                }
            } else {
                if ($this->_isRest()) {
                    $message = '';
                    foreach ($this->ShadowAttribute->validationErrors as $k => $v) {
                        $message .= '[' . $k . ']: ' . $v[0] . PHP_EOL;
                    }
                    throw new InternalErrorException(__('Could not save the proposal. Errors: %s', $message));
                } else {
                    $this->Flash->error(__('The proposed Attribute could not be saved. Please, try again.'));
                }
            }
        } else {
            // Read the attribute that we're about to edit
            $this->ShadowAttribute->create();
            $this->request->data['ShadowAttribute'] = $existingAttribute['Attribute'];
            unset($this->request->data['ShadowAttribute']['id']);
        }

        // combobox for types
        $types = $this->ShadowAttribute->Attribute->getNonAttachmentTypes();
        if ($existingAttribute['Attribute']['object_id']) {
            $this->set('objectAttribute', true);
        } else {
            $this->set('objectAttribute', false);
        }
        $types = $this->_arrayToValuesIndexArray($types);
        $this->set('types', $types);
        // combobox for categories
        $categories = $this->_arrayToValuesIndexArray(array_keys($this->ShadowAttribute->Attribute->categoryDefinitions));
        $categories = $this->_arrayToValuesIndexArray($categories);

        $categoryDefinitions = $this->ShadowAttribute->Attribute->categoryDefinitions;
        if ($existingAttribute['Attribute']['object_id']) {
            foreach ($categoryDefinitions as $k => $v) {
                if (!in_array($existingAttribute['Attribute']['type'], $v['types'])) {
                    unset($categoryDefinitions[$k]);
                }
            }
            foreach ($categories as $k => $v) {
                if (!isset($categoryDefinitions[$k])) {
                    unset($categories[$k]);
                }
            }
        }
        $this->set('event', ['Event' => $existingAttribute['Event']]);
        $this->set('categories', $categories);
        $this->__common();
        $this->set('attrDescriptions', $this->ShadowAttribute->fieldDescriptions);
        $this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
        $this->set('categoryDefinitions', $this->ShadowAttribute->Attribute->categoryDefinitions);
    }

    private function __common()
    {
        $fieldDesc = ['category' => [], 'type' => []];
        foreach ($this->ShadowAttribute->categoryDefinitions as $key => $value) {
            $fieldDesc['category'][$key] = isset($value['formdesc']) ? $value['formdesc'] : $value['desc'];
        }
        foreach ($this->ShadowAttribute->typeDefinitions as $key => $value) {
            $fieldDesc['type'][$key] = isset($value['formdesc']) ? $value['formdesc'] : $value['desc'];
        }
        $this->set('fieldDesc', $fieldDesc);
    }

    public function delete($id)
    {
        $existingAttribute = $this->ShadowAttribute->Event->Attribute->fetchAttributes(
            $this->Auth->user(),
            array('conditions' => $this->__attributeIdToConditions($id), 'flatten' => true)
        );
        if ($this->request->is('post')) {
            if (empty($existingAttribute)) {
                return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Invalid Attribute.')), 'status'=>200, 'type' => 'json'));
            }
            $existingAttribute = $existingAttribute[0];
            $this->ShadowAttribute->create();
            $sa = array(
                    'old_id' => $existingAttribute['Attribute']['id'],
                    'uuid' => $existingAttribute['Attribute']['uuid'],
                    'event_id' => $existingAttribute['Event']['id'],
                    'event_uuid' => $existingAttribute['Event']['uuid'],
                    'event_org_id' => $existingAttribute['Event']['orgc_id'],
                    'category' => $existingAttribute['Attribute']['category'],
                    'type' => $existingAttribute['Attribute']['type'],
                    'to_ids' => $existingAttribute['Attribute']['to_ids'],
                    'value' => $existingAttribute['Attribute']['value'],
                    'first_seen' => $existingAttribute['Attribute']['first_seen'],
                    'last_seen' => $existingAttribute['Attribute']['last_seen'],
                    'email' => $this->Auth->user('email'),
                    'org_id' => $this->Auth->user('org_id'),
                    'proposal_to_delete' => true,
            );
            if ($this->ShadowAttribute->save($sa)) {
                $emailResult = "";
                if (!$this->ShadowAttribute->sendProposalAlertEmail($existingAttribute['Event']['id'])) {
                    $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
                }
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'The proposal to delete the attribute has been saved' . $emailResult)), 'status'=>200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Could not create proposal.')), 'status'=>200, 'type' => 'json'));
            }
        } else {
            if (empty($existingAttribute)) {
                throw new NotFoundException(__('Invalid attribute'));
            }
            $existingAttribute = $existingAttribute[0];
            $this->set('id', $existingAttribute['Attribute']['id']);
            $this->set('event_id', $existingAttribute['Attribute']['event_id']);
            $this->render('ajax/deletionProposalConfirmationForm');
        }
    }

    public function view($id)
    {
        $conditions = $this->ShadowAttribute->buildConditions($this->Auth->user());
        $conditions['ShadowAttribute.id'] = $id;
        $conditions['ShadowAttribute.deleted'] = 0;

        $sa = $this->ShadowAttribute->find('first', array(
            'recursive' => -1,
            'contain' => ['Event', 'Attribute'], // required because of conditions
            'fields' => array(
                'ShadowAttribute.id', 'ShadowAttribute.old_id', 'ShadowAttribute.event_id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.uuid', 'ShadowAttribute.to_ids', 'ShadowAttribute.value', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.first_seen', 'ShadowAttribute.last_seen',
            ),
            'conditions' => $conditions,
        ));
        if (empty($sa)) {
            throw new NotFoundException(__('Invalid proposal.'));
        }
        $this->set('ShadowAttribute', $sa['ShadowAttribute']);
        $this->set('_serialize', array('ShadowAttribute'));
    }

    public function viewPicture($id, $thumbnail=false)
    {
        $conditions = $this->ShadowAttribute->buildConditions($this->Auth->user());
        $conditions['ShadowAttribute.id'] = $id;
        $conditions['ShadowAttribute.type'] = 'attachment';

        $sa = $this->ShadowAttribute->find('first', array(
            'recursive' => -1,
            'contain' => ['Event', 'Attribute'], // required because of conditions
            'fields' => array(
                'ShadowAttribute.id', 'ShadowAttribute.old_id', 'ShadowAttribute.event_id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.uuid', 'ShadowAttribute.to_ids', 'ShadowAttribute.value', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.first_seen', 'ShadowAttribute.last_seen',
            ),
            'conditions' => $conditions,
        ));
        if (empty($sa)) {
            throw new NotFoundException(__('Invalid proposal.'));
        }

        if (!$this->ShadowAttribute->Attribute->isImage($sa['ShadowAttribute'])) {
            throw new NotFoundException("ShadowAttribute is not an image.");
        }
        if ($this->_isRest()) {
            if ($this->ShadowAttribute->typeIsAttachment($sa['ShadowAttribute']['type'])) {
                $encodedFile = $this->ShadowAttribute->base64EncodeAttachment($sa['ShadowAttribute']);
                $sa['ShadowAttribute']['data'] = $encodedFile;
            }
        }

        if ($this->_isRest()) {
            return $this->RestResponse->viewData($sa['ShadowAttribute']['data'], $this->response->type());
        } else {
            $width = isset($this->request->params['named']['width']) ? $this->request->params['named']['width'] : 200;
            $height = isset($this->request->params['named']['height']) ? $this->request->params['named']['height'] : 200;
            $imageData = $this->ShadowAttribute->getPictureData($sa, $thumbnail, $width, $height);
            $extension = pathinfo($sa['ShadowAttribute']['value'], PATHINFO_EXTENSION);
            return new CakeResponse(array('body' => $imageData, 'type' => strtolower($extension)));
        }
    }

    public function index($eventId = false)
    {
        $conditions = array();
        if (isset($this->request['named']['all'])) {
            $all = $this->request['named']['all'];
        } else {
            $all = 1;
        }
        $eventId = $this->Toolbox->findIdByUuid($this->ShadowAttribute->Event, $eventId, true);
        if ($eventId) {
            $conditions['ShadowAttribute.event_id'] = $eventId;
        }
        $temp = $this->ShadowAttribute->buildConditions($this->Auth->user());
        if (!empty($temp)) {
            $conditions['AND'][] = $temp;
        }
        unset($temp);
        if (empty($all)) {
            $conditions['AND'][] = array('Event.orgc_id' =>$this->Auth->user('org_id'));
        }
        if (!empty($this->request['named']['searchall'])) {
            $term = '%' . strtolower(trim($this->request['named']['searchall'])) . '%';
            $conditions['AND'][] = array('OR' => array(
                'LOWER(ShadowAttribute.value1) LIKE' => $term,
                'LOWER(ShadowAttribute.value2) LIKE' => $term,
                'LOWER(ShadowAttribute.comment) LIKE' => $term,
                'LOWER(Event.info) LIKE' => $term,
                'LOWER(Org.name) LIKE' => $term,
                'LOWER(Org.uuid) LIKE' => $term,
                'LOWER(ShadowAttribute.uuid) LIKE' => $term,
                'LOWER(Event.uuid) LIKE' => $term,
            ));
        }
        if (isset($this->request['named']['deleted'])) {
            $conditions['AND'][] = array(
                'ShadowAttribute.deleted' => $this->request['named']['deleted']
            );
       }
        if (!empty($this->request['named']['timestamp'])) {
            $conditions['AND'][] = array(
                'ShadowAttribute.timestamp >=' => $this->request['named']['timestamp']
            );
        }
        if (!$this->_isRest() && !isset($this->request['named']['deleted'])) {
            $conditions['AND'][] = array('ShadowAttribute.deleted' => 0);
        }
        $params = array(
            'conditions' => $conditions,
            'fields' => array(
                'ShadowAttribute.id',
                'ShadowAttribute.old_id',
                'ShadowAttribute.event_id',
                'ShadowAttribute.type',
                'ShadowAttribute.category',
                'ShadowAttribute.uuid',
                'ShadowAttribute.to_ids',
                'ShadowAttribute.value',
                'ShadowAttribute.comment',
                'ShadowAttribute.org_id',
                'ShadowAttribute.timestamp',
                'ShadowAttribute.first_seen',
                'ShadowAttribute.last_seen',
                'ShadowAttribute.deleted',
                'ShadowAttribute.proposal_to_delete',
                'ShadowAttribute.disable_correlation'
            ),
            'contain' => array(
                    'Event' => array(
                            'fields' => array('id', 'org_id', 'info', 'orgc_id', 'uuid'),
                            'Orgc' => array('fields' => array('Orgc.name', 'Orgc.id', 'Orgc.uuid'))
                    ),
                    'Org' => array(
                        'fields' => array('name', 'uuid'),
                    ),
                    'Attribute' => array(
                        'fields' => array('uuid'),
                        'Object'
                    ),
            ),
            'recursive' => -1
        );
        $simpleParams = array('limit', 'page');
        foreach ($simpleParams as $simpleParam) {
            if (!empty($this->request['named'][$simpleParam])) {
                $params[$simpleParam] = $this->request['named'][$simpleParam];
            }
        }
        if (isset($this->request['named']['sort'])) {
            $params['order'] = 'ShadowAttribute.' . $this->request['named']['sort'];
            if (!empty($this->request['named']['direction'])) {
                $direction = trim(strtolower($this->request['named']['direction']));
                $params['order'] .= ' ' . ($direction === 'asc' ? 'ASC' : 'DESC');
            } else {
                $params['order'] .= ' ASC';
            }
        }
        if ($this->_isRest()) {
            $results = $this->ShadowAttribute->find('all', $params);
            foreach ($results as $k => $result) {
                $result['ShadowAttribute']['org_uuid'] = $result['Org']['uuid'];
                if (!empty($result['ShadowAttribute']['old_id'])) {
                    $result['ShadowAttribute']['old_uuid'] = $result['Attribute']['uuid'];
                }
                $result['ShadowAttribute']['event_uuid'] = $result['Event']['uuid'];
                $result['ShadowAttribute']['Org'] = $result['Org'];
                if (isset($result['ShadowAttribute']['type']) && $this->ShadowAttribute->typeIsAttachment($result['ShadowAttribute']['type']) && !empty($result['ShadowAttribute']['data'])) {
                    $result = $result && $this->ShadowAttribute->saveBase64EncodedAttachment($result['ShadowAttribute']);
                }
                $results[$k] = array('ShadowAttribute' => $result['ShadowAttribute']);
            }
            return $this->RestResponse->viewData($results, $this->response->type());
        } else {
            $this->paginate = $params;
            $results = $this->paginate();
            foreach ($results as $k => $result) {
                unset($results[$k]['Attribute']);
            }
            $this->set('shadowAttributes', $results);
            $this->set('all', $all);
        }
    }

    public function discardSelected($id)
    {
        if (!$this->request->is('post') || !$this->request->is('ajax')) {
            throw new MethodNotAllowedException();
        }

        // get a json object with a list of proposal IDs to be discarded
        // check each of them and return a json object with the successful discards and the failed ones.
        $ids = json_decode($this->request->data['ShadowAttribute']['ids_discard']);
        if (!$this->_isSiteAdmin()) {
            $event = $this->ShadowAttribute->Event->find('first', array(
                    'conditions' => array('id' => $id),
                    'recursive' => -1,
                    'fields' => array('id', 'orgc_id', 'user_id')
            ));
            if (!$event) {
                return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Invalid event.')), 'status' => 200, 'type' => 'json'));
            }
            if (!$this->__canModifyEvent($event)) {
                return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
            }
        }

        // find all attributes from the ID list that also match the provided event ID.
        $shadowAttributes = $this->ShadowAttribute->find('list', array(
                'recursive' => -1,
                'conditions' => array('id' => $ids, 'event_id' => $id),
                'fields' => array('id')
        ));
        $successes = array();
        foreach ($shadowAttributes as $id) {
            if ($this->__discard($id)) {
                $successes[] = $id;
            }
        }
        $fails = array_diff($ids, $successes);
        $this->autoRender = false;
        if (count($fails) == 0 && count($successes) > 0) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' deleted.')), 'status'=>200, 'type' => 'json'));
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' deleted, but ' . count($fails) . ' proposal' . (count($fails) != 1 ? 's' : '') . ' could not be deleted.')), 'status'=>200, 'type' => 'json'));
        }
    }

    public function acceptSelected($id)
    {
        if (!$this->request->is('post') || !$this->request->is('ajax')) {
            throw new MethodNotAllowedException();
        }

        // get a json object with a list of proposal IDs to be accepted
        // check each of them and return a json object with the successful accepts and the failed ones.
        $ids = json_decode($this->request->data['ShadowAttribute']['ids_accept']);
        if (!$this->_isSiteAdmin()) {
            $event = $this->ShadowAttribute->Event->find('first', array(
                    'conditions' => array('id' => $id),
                    'recursive' => -1,
                    'fields' => array('id', 'orgc_id', 'user_id')
            ));
            if (!$event) {
                return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Invalid event.')), 'status' => 200, 'type' => 'json'));
            }
            if (!$this->__canModifyEvent($event)) {
                return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
            }
        }

        // find all attributes from the ID list that also match the provided event ID.
        $shadowAttributes = $this->ShadowAttribute->find('list', array(
                'recursive' => -1,
                'conditions' => array('id' => $ids, 'event_id' => $id),
                'fields' => array('id')
        ));
        $successes = array();
        foreach ($shadowAttributes as $shadowAttributeId) {
            $response = $this->__accept($shadowAttributeId);
            if (isset($response['saved'])) {
                $successes[] = $shadowAttributeId;
            }
        }
        $this->ShadowAttribute->Event->unpublishEvent($id, true);
        $fails = array_diff($ids, $successes);
        $this->autoRender = false;
        if (count($fails) == 0 && count($successes) > 0) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' accepted.')), 'status'=>200, 'type' => 'json'));
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' accepted, but ' . count($fails) . ' proposal' . (count($fails) != 1 ? 's' : '') . ' could not be accepted.')), 'status'=>200, 'type' => 'json'));
        }
    }

    public function generateCorrelation()
    {
        if (!self::_isSiteAdmin() || !$this->request->is('post')) {
            throw new NotFoundException();
        }
        if (!Configure::read('MISP.background_jobs')) {
            $k = $this->ShadowAttribute->generateCorrelation();
            $this->Flash->success(__('All done. ' . $k . ' proposals processed.'));
            $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
        } else {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generate proposal correlation',
                'All attributes',
                'Job created.'
            );

            $this->MispAttribute->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'jobGenerateShadowAttributeCorrelation',
                    $jobId
                ],
                true,
                $jobId
            );

            $this->Flash->success(__('Job queued. You can view the progress if you navigate to the active jobs view (administration -> jobs).'));
            $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
        }
    }

    private function __attributeIdToConditions($id)
    {
        if (is_numeric($id)) {
            $conditions = array('Attribute.id' => $id);
        } elseif (Validation::uuid($id)) {
            $conditions = array('Attribute.uuid' => $id);
        } else {
            throw new NotFoundException(__('Invalid attribute ID.'));
        }
        return $conditions;
    }
}
