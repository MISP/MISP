<?php
App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('AttachmentTool', 'Tools');

/**
 * @property Attribute $Attribute
 */
class AttributesController extends AppController
{
    public $components = array('RequestHandler');

    public $paginate = [
        'limit' => 60,
        'maxLimit' => 9999,
        'conditions' => array('AND' => array('Attribute.deleted' => 0)),
        'order' => 'Attribute.event_id DESC',
        'recursive' => -1,
        'contain' => array(
            'Event' => array(
                'fields' =>  array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.info', 'Event.user_id', 'Event.date'),
            ),
            'AttributeTag',
            'Object' => array(
                'fields' => array('Object.id', 'Object.distribution', 'Object.sharing_group_id')
            ),
            'SharingGroup' => ['fields' => ['SharingGroup.name']],
        ),
    ];

    public function beforeFilter()
    {
        parent::beforeFilter();

        // permit reuse of CSRF tokens on the search page.
        if ('search' === $this->request->params['action']) {
            $this->Security->csrfCheck = false;
        }
        $this->Security->unlockedActions[] = 'getMassEditForm';
        $this->Security->unlockedActions[] = 'search';

        if ($this->request->action === 'add_attachment') {
            $this->Security->unlockedFields = array('values');
        } elseif ($this->request->action === 'viewPicture') {
            $this->Security->doNotGenerateToken = true;
        }
    }

    public function index()
    {
        $user = $this->Auth->user();
        $this->paginate['conditions']['AND'][] = $this->Attribute->buildConditions($user);

        $this->__setIndexFilterConditions();

        $attributes = $this->paginate();

        if ($this->_isRest()) {
            $attributes = array_column($attributes, 'Attribute');
            return $this->RestResponse->viewData($attributes, $this->response->type());
        }

        $this->Attribute->attachTagsToAttributes($attributes, ['includeAllTags' => true]);
        $orgTable = $this->Attribute->Event->Orgc->find('all', [
            'fields' => ['Orgc.id', 'Orgc.name', 'Orgc.uuid'],
        ]);
        $orgTable = Hash::combine($orgTable, '{n}.Orgc.id', '{n}.Orgc');
        $sgids = $this->Attribute->SharingGroup->authorizedIds($user);
        foreach ($attributes as &$attribute) {
            if (isset($orgTable[$attribute['Event']['orgc_id']])) {
                $attribute['Event']['Orgc'] = $orgTable[$attribute['Event']['orgc_id']];
            }
            $temp = $this->Attribute->Correlation->getRelatedAttributes(
                $user,
                $sgids,
                $attribute['Attribute'],
                [],
                true
            );
            foreach ($temp as &$t) {
                $t['info'] = $t['Event']['info'];
                $t['org_id'] = $t['Event']['org_id'];
                $t['date'] = $t['Event']['date'];
            }
            $attribute['Event']['RelatedAttribute'][$attribute['Attribute']['id']] = $temp;
        }

        list($attributes, $sightingsData) = $this->__searchUI($attributes, $user);
        $this->set('isSearch', 0);
        $this->set('sightingsData', $sightingsData);
        $this->set('orgTable', array_column($orgTable, 'name', 'id'));
        $this->set('shortDist', $this->Attribute->shortDist);
        $this->set('attributes', $attributes);
        $this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
        $this->set('typeDefinitions', $this->Attribute->typeDefinitions);
        $this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
        $this->set('distributionLevels', $this->Attribute->distributionLevels);
    }

    public function add($eventId = false)
    {
        if ($this->request->is('get') && $this->_isRest()) {
            return $this->RestResponse->describe('Attributes', 'add', false, $this->response->type());
        }
        if ($eventId === false) {
            throw new MethodNotAllowedException(__('No event ID set.'));
        }
        $event = $this->Attribute->Event->fetchSimpleEvent($this->Auth->user(), $eventId, ['contain' => ['Orgc']]);
        if (!$event) {
            throw new NotFoundException(__('Invalid event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        if (!$this->_isRest()) {
            $this->Attribute->Event->insertLock($this->Auth->user(), $event['Event']['id']);
        }
        if ($this->request->is('ajax')) {
            $this->set('ajax', true);
            $this->layout = false;
        } else {
            $this->set('ajax', false);
        }
        if ($this->request->is('post')) {
            if ($this->request->is('ajax')) {
                $this->autoRender = false;
            }
            if (!isset($this->request->data['Attribute'])) {
                $this->request->data = array('Attribute' => $this->request->data);
            }
            if (isset($this->request->data['Attribute']['distribution']) && $this->request->data['Attribute']['distribution'] == 4) {
                if (!$this->__canUseSharingGroup($this->request->data['Attribute']['sharing_group_id'])) {
                    throw new ForbiddenException(__('Invalid Sharing Group or not authorised.'));
                }
            }
            //
            // multiple attributes in batch import
            //
            if (!empty($this->request->data['Attribute']['batch_import']) || (!empty($this->request->data['Attribute']['value']) && is_array($this->request->data['Attribute']['value']))) {
                $attributes = array();
                if (is_array($this->request->data['Attribute']['value'])) {
                    $values = $this->request->data['Attribute']['value'];
                } else {
                    $values = explode("\n", rtrim($this->request->data['Attribute']['value'], "\n"));
                }
                $temp = $this->request->data['Attribute'];
                foreach ($values as $value) {
                    $temp['value'] = $value;
                    $attributes[] = $temp;
                }
            } else {
                $attributes = $this->request->data['Attribute'];
            }
            if (!isset($attributes[0])) {
                $attributes = array(0 => $attributes);
            }
            $fails = [];
            $successes = 0;
            $attributeCount = count($attributes);
            $insertedIds = array();
            foreach ($attributes as $k => $attribute) {
                $validationErrors = array();
                $this->Attribute->captureAttribute($attribute, $event['Event']['id'], $this->Auth->user(), false, false, $event, $validationErrors, $this->params['named']);
                if (empty($validationErrors)) {
                    $insertedIds[] = $this->Attribute->id;
                    $successes++;
                } else {
                    $fails["attribute_" . $k] = $validationErrors;
                }
            }
            if ($successes !== 0) {
                $this->Attribute->Event->unpublishEvent($event);
            }
            if ($this->_isRest()) {
                if ($successes !== 0) {
                    $attributes = $this->Attribute->find('all', array(
                        'recursive' => -1,
                        'conditions' => array('Attribute.id' => $insertedIds),
                        'contain' => array(
                            'AttributeTag' => array(
                                'Tag' => array('fields' => array('Tag.id', 'Tag.name', 'Tag.colour', 'Tag.numerical_value'))
                            )
                        )
                    ));
                    if (count($attributes) === 1) {
                        $attributes = $attributes[0];
                    } else {
                        $result = array('Attribute' => array());
                        foreach ($attributes as $attribute) {
                            $temp = $attribute['Attribute'];
                            if (!empty($attribute['AttributeTag'])) {
                                foreach ($attribute['AttributeTag'] as $at) {
                                    $temp['Tag'][] = $at['Tag'];
                                }
                            }
                            $result['Attribute'][] = $temp;
                        }
                        $attributes = $result;
                        unset($result);
                    }
                    return $this->RestResponse->viewData($attributes, $this->response->type(), $fails);
                } else {
                    if ($attributeCount === 1) {
                        return $this->RestResponse->saveFailResponse('Attributes', 'add', false, $fails["attribute_0"], $this->response->type());
                    } else {
                        return $this->RestResponse->saveFailResponse('Attributes', 'add', false, $fails, $this->response->type());
                    }
                }
            } else {
                if (empty($fails)) {
                    $message = __('Attributes saved.');
                } else {
                    if ($attributeCount > 1) {
                        $flashErrorMessage = [];
                        foreach ($attributes as $k => $attribute) {
                            if (isset($fails["attribute_$k"])) {
                                $reason = '';
                                foreach ($fails["attribute_" . $k] as $failKey => $failData) {
                                    $reason = $failKey . ': ' . $failData[0];
                                }
                                $flashErrorMessage[] = '<span class="red bold">' . h($attribute["value"]) . '</span> (' . h($reason) . ')';
                            } else {
                                $flashErrorMessage[] = '<span class="green bold">' . h($attribute["value"]) . '</span>';
                            }
                        }
                        $flashErrorMessage = implode('<br>', $flashErrorMessage);
                        $this->Session->write('flashErrorMessage', $flashErrorMessage);

                        if ($successes === 0) {
                            $message = __('Attributes could not be saved. Click $flashErrorMessage for more info');
                        } else {
                            $message = __('Attributes saved, however, %s attributes could not be saved. Click $flashErrorMessage for more info', count($fails));
                        }
                    } else {
                        $message = __('Attribute could not be saved.');
                    }
                }
                if ($this->request->is('ajax')) {
                    if (!empty($successes)) {
                        $data = ['saved' => true, 'success' => $message];
                    } else {
                        $message = $attributeCount > 1 ? $message : $this->Attribute->validationErrors;
                        $data = ['saved' => false, 'errors' => $message];
                        if (!empty($flashErrorMessage)) {
                            $data['full_errors'] = $flashErrorMessage;
                        }
                    }
                    return $this->RestResponse->viewData($data, 'json');
                }
                if (empty($fails)) {
                    $this->Flash->success($message);
                } else {
                    $this->Flash->error($message);
                }
                if ($successes > 0) {
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $event['Event']['id']));
                }
            }
        }
        // combobox for types
        $types = $this->Attribute->getNonAttachmentTypes();
        $types = $this->_arrayToValuesIndexArray($types);
        $this->set('types', $types);
        // combobox for categories
        $categories = array_keys($this->Attribute->categoryDefinitions);
        $categories = $this->_arrayToValuesIndexArray($categories);
        $this->set('categories', $categories);
        $this->__common();
        $this->set('title_for_layout', __('Add attribute'));
        $this->set('typeDefinitions', $this->Attribute->typeDefinitions);
        $this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
        $this->set('event', $event);
        $this->set('action', $this->request->action);
    }

    public function download($id = null)
    {
        $conditions = $this->__idToConditions($id);
        $conditions['Attribute.type'] = array('attachment', 'malware-sample');
        $attributes = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => $conditions, 'flatten' => true));
        if (empty($attributes)) {
            throw new UnauthorizedException(__('Attribute does not exist or you do not have the permission to download this attribute.'));
        }
        return $this->__downloadAttachment($attributes[0]['Attribute']);
    }

    private function __downloadAttachment(array $attribute)
    {
        $file = $this->Attribute->getAttachmentFile($attribute);

        if ('attachment' === $attribute['type']) {
            $filename = $attribute['value'];
            $fileExt = pathinfo($filename, PATHINFO_EXTENSION);
            $filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
        } elseif ('malware-sample' === $attribute['type']) {
            $filenameHash = explode('|', $attribute['value']);
            $filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
            $fileExt = "zip";
        } else {
            throw new NotFoundException(__('Attribute not an attachment or malware-sample'));
        }

        $download_attachments_on_load = Configure::check('MISP.download_attachments_on_load') ? Configure::read('MISP.download_attachments_on_load') : true;
        return $this->RestResponse->sendFile($file, $fileExt, $download_attachments_on_load, $filename . '.' . $fileExt);
    }

    public function add_attachment($eventId = null)
    {
        $event = $this->Attribute->Event->fetchSimpleEvent($this->Auth->user(), $eventId, ['contain' => ['Orgc']]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event.'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }

        if ($this->request->is('post')) {
            if (isset($this->request->data['Attribute']['distribution']) && $this->request->data['Attribute']['distribution'] == 4) {
                if (!$this->__canUseSharingGroup($this->request->data['Attribute']['sharing_group_id'])) {
                    throw new ForbiddenException(__('Invalid Sharing Group or not authorised.'));
                }
            }

            $fails = array();
            $success = 0;

            foreach ($this->request->data['Attribute']['values'] as $value) {
                // Check if there were problems with the file upload
                // only keep the last part of the filename, this should prevent directory attacks
                $filename = basename($value['name']);
                $tmpfile = new File($value['tmp_name']);
                if ((isset($value['error']) && $value['error'] == 0) ||
                    (!empty($value['tmp_name']) && $value['tmp_name'] != 'none')
                ) {
                    if (!is_uploaded_file($tmpfile->path)) {
                        throw new InternalErrorException(__('PHP says file was not uploaded. Are you attacking me?'));
                    }
                } else {
                    $fails[] = $filename;
                    continue;
                }

                if ($this->request->data['Attribute']['malware']) {
                    if ($this->request->data['Attribute']['advanced']) {
                        $result = $this->Attribute->advancedAddMalwareSample(
                            $event['Event']['id'],
                            $this->request->data['Attribute'],
                            $filename,
                            $tmpfile
                        );
                    } else {
                        $result = $this->Attribute->simpleAddMalwareSample(
                            $event['Event']['id'],
                            $this->request->data['Attribute'],
                            $filename,
                            $tmpfile
                        );
                    }

                    if ($result) {
                        $success++;
                    } else {
                        $fails[] = $filename;
                    }

                    if (!empty($result)) {
                        foreach ($result['Object'] as $object) {
                            $object['distribution'] = $this->request->data['Attribute']['distribution'];
                            if (!empty($this->request->data['sharing_group_id'])) {
                                $object['sharing_group_id'] = $this->request->data['Attribute']['sharing_group_id'];
                            }
                            foreach ($object['Attribute'] as $ka => $attribute) {
                                $object['Attribute'][$ka]['distribution'] = 5;
                            }
                            $this->Attribute->Object->captureObject(array('Object' => $object), $event['Event']['id'], $this->Auth->user());
                        }
                        if (!empty($result['ObjectReference'])) {
                            foreach ($result['ObjectReference'] as $reference) {
                                $this->Attribute->Object->ObjectReference->smartSave($reference, $event['Event']['id']);
                            }
                        }
                    }
                } else {
                    $attribute = array(
                        'Attribute' => array(
                            'value' => $filename,
                            'category' => $this->request->data['Attribute']['category'],
                            'type' => 'attachment',
                            'event_id' => $event['Event']['id'],
                            'data_raw' => $tmpfile->read(),
                            'comment' => $this->request->data['Attribute']['comment'],
                            'to_ids' => 0,
                            'distribution' => $this->request->data['Attribute']['distribution'],
                            'sharing_group_id' => isset($this->request->data['Attribute']['sharing_group_id']) ? $this->request->data['Attribute']['sharing_group_id'] : 0,
                        )
                    );
                    $this->Attribute->create();
                    $r = $this->Attribute->save($attribute);
                    if ($r == false) {
                        $fails[] = $filename;
                    } else {
                        $success++;
                    }
                }
            }
            $message = __n('The attachment have been uploaded.', 'The attachments have been uploaded.', $success);
            if (!empty($fails)) {
                $message = __('Some of the attachments failed to upload. The failed files were: %s - This can be caused by the attachments already existing in the event.', implode(', ', $fails));
            }
            if (empty($success)) {
                if (empty($fails)) {
                    $message = __('The attachment(s) could not be saved. Please contact your administrator.');
                }
            } else {
                $this->Attribute->Event->unpublishEvent($event);
            }
            if (empty($success) && !empty($fails)) {
                $this->Flash->error($message);
            } else {
                $this->Flash->success($message);
            }
            if (!$this->_isRest()) {
                $this->Attribute->Event->insertLock($this->Auth->user(), $event['Event']['id']);
            }
            $this->redirect(array('controller' => 'events', 'action' => 'view', $event['Event']['id']));
        } else {
            // set the event_id in the form
            $this->request->data['Attribute']['event_id'] = $event['Event']['id'];
        }

        if (!$this->_isRest()) {
            $this->Attribute->Event->insertLock($this->Auth->user(), $event['Event']['id']);
        }

        // Filter categories that contains attachment type
        $selectedCategories = array();
        foreach ($this->Attribute->categoryDefinitions as $category => $values) {
            foreach ($values['types'] as $type) {
                if ($this->Attribute->typeIsAttachment($type)) {
                    $selectedCategories[] = $category;
                    break;
                }
            }
        }

        // Create list of categories that should be marked as malware sample by default
        $isMalwareSampleCategory = [];
        foreach ($selectedCategories as $category) {
            $possibleMalwareSample = false;
            foreach ($this->Attribute->categoryDefinitions[$category]['types'] as $type) {
                if ($this->Attribute->typeIsMalware($type)) {
                    $possibleMalwareSample = true;
                    break;
                }
            }
            $isMalwareSampleCategory[$category] = $possibleMalwareSample;
        }

        $categories = $this->_arrayToValuesIndexArray($selectedCategories);
        $this->set('categories', $categories);

        $this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
        $this->set('isMalwareSampleCategory', $isMalwareSampleCategory);
        $this->set('advancedExtractionAvailable', $this->Attribute->isAdvancedExtractionAvailable());
        $this->__common();
        $this->set('title_for_layout', __('Add attachment'));
        $this->set('event', $event);
    }

    private function __common()
    {
        $distributionData = $this->Attribute->fetchDistributionData($this->Auth->user());
        $this->set('sharingGroups', $distributionData['sgs']);
        $this->set('distributionLevels', $distributionData['levels']);
        $this->set('initialDistribution', $distributionData['initial']);
        $this->set('fieldDesc', $this->__fieldDesc());
        $this->set('nonCorrelatingTypes', Attribute::NON_CORRELATING_TYPES);

        $this->loadModel('Noticelist');
        $notice_list_triggers = $this->Noticelist->getTriggerData();
        $this->set('notice_list_triggers', json_encode($notice_list_triggers));
    }

    /**
     * @return array|array[]
     */
    private function __fieldDesc()
    {
        $fieldDesc = ['category' => [], 'type' => [], 'distribution' => []];
        foreach ($this->Attribute->categoryDefinitions as $key => $value) {
            $fieldDesc['category'][$key] = isset($value['formdesc']) ? $value['formdesc'] : $value['desc'];
        }
        foreach ($this->Attribute->typeDefinitions as $key => $value) {
            $fieldDesc['type'][$key] = isset($value['formdesc']) ? $value['formdesc'] : $value['desc'];
        }
        foreach ($this->Attribute->distributionLevels as $key => $value) {
            $fieldDesc['distribution'][$key] = $this->Attribute->distributionDescriptions[$key]['formdesc'];
        }
        return $fieldDesc;
    }

    // Imports the CSV threatConnect file to multiple attributes
    public function add_threatconnect($eventId = null)
    {
        if ($this->request->is('post')) {
            $this->loadModel('Event');
            $this->Event->id = $eventId;
            $this->Event->recursive = -1;
            $this->Event->read();
            if (!$this->__canModifyEvent($this->Event->data)) {
                throw new ForbiddenException(__('You do not have permission to do that.'));
            }
            //
            // File upload
            //
            // Check if there were problems with the file upload
            $tmpfile = new File($this->request->data['Attribute']['value']['tmp_name']);
            if ((isset($this->request->data['Attribute']['value']['error']) && $this->request->data['Attribute']['value']['error'] == 0) ||
                    (!empty($this->request->data['Attribute']['value']['tmp_name']) && $this->request->data['Attribute']['value']['tmp_name'] != 'none')
            ) {
                if (!is_uploaded_file($tmpfile->path)) {
                    throw new InternalErrorException(__('PHP says file was not uploaded. Are you attacking me?'));
                }
            } else {
                $this->Flash->error(__('There was a problem to upload the file.', true), 'default', array(), 'error');
                $this->redirect(array('controller' => 'attributes', 'action' => 'add_threatconnect', $this->request->data['Attribute']['event_id']));
            }
            // verify mime type
            $file_info = $tmpfile->info();
            if ($file_info['mime'] != 'text/plain') {
                $this->Flash->error('File not in CSV format.', 'default', array(), 'error');
                $this->redirect(array('controller' => 'attributes', 'action' => 'add_threatconnect', $this->request->data['Attribute']['event_id']));
            }

            // parse uploaded csv file
            $filename = $tmpfile->path;
            $header = null;
            $entries = array();
            if (($handle = fopen($filename, 'r')) !== false) {
                while (($row = fgetcsv($handle, 0, ',', '"')) !== false) {
                    if (!$header) {
                        $header = $row;
                    } else {
                        $entries[] = array_combine($header, $row);
                    }
                }
                fclose($handle);
            }
            // verify header of the file (first row)
            $required_headers = array('Type', 'Value', 'Confidence', 'Description', 'Source');

            // TODO i18n
            if (count(array_intersect($header, $required_headers)) != count($required_headers)) {
                $this->Flash->error('Incorrect ThreatConnect headers. The minimum required headers are: '.implode(',', $required_headers), 'default', array(), 'error');
                $this->redirect(array('controller' => 'attributes', 'action' => 'add_threatconnect', $this->request->data['Attribute']['event_id']));
            }

            //
            // import attributes
            //
            $attributes = array();  // array with all the attributes we're going to save
            foreach ($entries as $entry) {
                $attribute = array();
                $attribute['event_id'] = $this->request->data['Attribute']['event_id'];
                $attribute['value'] = $entry['Value'];
                $attribute['to_ids'] = ($entry['Confidence'] > 51) ? 1 : 0; // To IDS if high confidence
                $attribute['comment'] = $entry['Description'];
                $attribute['distribution'] = '3'; // 'All communities'
                if (Configure::read('MISP.default_attribute_distribution') != null) {
                    if (Configure::read('MISP.default_attribute_distribution') === 'event') {
                        $attribute['distribution'] = $this->Event->data['Event']['distribution'];
                    } else {
                        $attribute['distribution'] = Configure::read('MISP.default_attribute_distribution');
                    }
                }
                switch ($entry['Type']) {
                    case 'Address':
                        $attribute['category'] = 'Network activity';
                        $attribute['type'] = 'ip-dst';
                        break;
                    case 'Host':
                        $attribute['category'] = 'Network activity';
                        $attribute['type'] = 'domain';
                        break;
                    case 'EmailAddress':
                        $attribute['category'] = 'Payload delivery';
                        $attribute['type'] = 'email-src';
                        break;
                    case 'File':
                        $attribute['category'] = 'Artifacts dropped';
                        $attribute['value'] = strtolower($attribute['value']);
                        if (preg_match("#^[0-9a-f]{32}$#", $attribute['value'])) {
                            $attribute['type'] = 'md5';
                        } elseif (preg_match("#^[0-9a-f]{40}$#", $attribute['value'])) {
                            $attribute['type'] = 'sha1';
                        } elseif (preg_match("#^[0-9a-f]{64}$#", $attribute['value'])) {
                            $attribute['type'] = 'sha256';
                        } else {
                            // do not keep attributes that do not have a match
                            $attribute=null;
                        }
                        break;
                    case 'URL':
                        $attribute['category'] = 'Network activity';
                        $attribute['type'] = 'url';
                        break;
                    default:
                        // do not keep attributes that do not have a match
                        $attribute=null;
                }
                // add attribute to the array that will be saved
                if ($attribute) {
                    $attributes[] = $attribute;
                }
            }

            //
            // import source info:
            //
            // 1/ iterate over all the sources, unique
            // 2/ add uniques as 'Internal reference'
            // 3/ if url format -> 'link'
            //    else 'comment'
            $references = array();
            foreach ($entries as $entry) {
                if (empty($entry['Source'])) {
                    continue;
                }
                $references[$entry['Source']] = true;
            }
            $references = array_keys($references);
            // generate the Attributes
            foreach ($references as $reference) {
                $attribute = array();
                $attribute['event_id'] = $this->request->data['Attribute']['event_id'];
                $attribute['category'] = 'Internal reference';
                if (preg_match('#^(http|ftp)(s)?\:\/\/((([a-z|0-9|\-]{1,25})(\.)?){2,7})($|/.*$)#i', $reference)) {
                    $attribute['type'] = 'link';
                } else {
                    $attribute['type'] = 'comment';
                }
                $attribute['value'] = $reference;
                $attribute['distribution'] = 3; // 'All communities'
                // add attribute to the array that will be saved
                $attributes[] = $attribute;
            }

            //
            // finally save all the attributes at once, and continue if there are validation errors
            //

            $results = array('successes' => 0, 'fails' => 0);
            foreach ($attributes as $attribute) {
                $this->Attribute->create();
                $result = $this->Attribute->save($attribute);
                if (!$result) {
                    $results['fails']++;
                } else {
                    $results['successes']++;
                }
            }
            // data imported (with or without errors)
            // remove the published flag from the event
            $this->loadModel('Event');
            $this->Event->id = $this->request->data['Attribute']['event_id'];
            $this->Event->saveField('published', 0);

            // everything is done, now redirect to event view
            $message = __('The ThreatConnect data has been imported.');
            if ($results['successes'] != 0) {
                $flashType = 'success';
                $temp = sprintf(__('%s entries imported.'), $results['successes']);
                $message .= ' ' . $temp;
            }
            if ($results['fails'] != 0) {
                $temp = sprintf(__('%s entries could not be imported.'), $results['fails']);
                $message .= ' ' . $temp;
            }
            $this->Flash->{empty($flashType) ? 'error' : $flashType}($message);
            $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
        } else {
            // set the event_id in the form
            $this->request->data['Attribute']['event_id'] = $eventId;
        }

        // form not submitted, show page
        $this->loadModel('Event');
        $events = $this->Event->findById($eventId);
        $this->set('published', $events['Event']['published']);
    }

    public function edit($id = null)
    {
        if ($this->request->is('get') && $this->_isRest()) {
            return $this->RestResponse->describe('Attributes', 'edit', false, $this->response->type());
        }
        $attribute = $this->__fetchAttribute($id);
        if (empty($attribute)) {
            throw new NotFoundException('Invalid attribute');
        }
        $this->Attribute->data = $attribute;
        if ($this->Attribute->data['Attribute']['deleted']) {
            throw new NotFoundException(__('Invalid attribute'));
        }
        $this->Attribute->id = $attribute['Attribute']['id'];
        if (!$this->__canModifyEvent($attribute)) {
            $message = __('You do not have permission to do that.');
            if ($this->_isRest()) {
                throw new ForbiddenException($message);
            } else {
                $this->Flash->error($message);
                $this->redirect(array('controller' => 'events', 'action' => 'index'));
            }
        }
        if (!$this->_isRest()) {
            $this->Attribute->Event->insertLock($this->Auth->user(), $this->Attribute->data['Attribute']['event_id']);
        }
        $eventId = $this->Attribute->data['Attribute']['event_id'];

        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['Attribute'])) {
                $this->request->data = array('Attribute' => $this->request->data);
            }
            if (isset($this->request->data['Attribute']['distribution']) && $this->request->data['Attribute']['distribution'] == 4) {
                if (!$this->__canUseSharingGroup($this->request->data['Attribute']['sharing_group_id'])) {
                    throw new ForbiddenException(__('Invalid Sharing Group or not authorised.'));
                }
            }
            $dateObj = new DateTime();
            $existingAttribute = $this->Attribute->find('first', [
                    'conditions' => [
                        'Attribute.uuid' => $this->Attribute->data['Attribute']['uuid']
                    ],
                    'recursive' => -1
                ]
            );
            // check if the attribute has a timestamp already set (from a previous instance that is trying to edit via synchronisation)
            // check which attribute is newer
            if (count($existingAttribute) && !$existingAttribute['Attribute']['deleted']) {
                $this->request->data['Attribute']['id'] = $existingAttribute['Attribute']['id'];
                $this->request->data['Attribute']['event_id'] = $existingAttribute['Attribute']['event_id'];
                $this->request->data['Attribute']['object_id'] = $existingAttribute['Attribute']['object_id'];
                $this->request->data['Attribute']['uuid'] = $existingAttribute['Attribute']['uuid'];
                $skipTimeCheck = false;
                if (!isset($this->request->data['Attribute']['timestamp'])) {
                    $this->request->data['Attribute']['timestamp'] = $dateObj->getTimestamp();
                    $skipTimeCheck = true;
                }
                if ($skipTimeCheck || $this->request->data['Attribute']['timestamp'] > $existingAttribute['Attribute']['timestamp']) {
                    $recoverFields = array('value', 'to_ids', 'distribution', 'category', 'type', 'comment', 'first_seen', 'last_seen');
                    foreach ($recoverFields as $rF) {
                        if (!isset($this->request->data['Attribute'][$rF])) {
                            $this->request->data['Attribute'][$rF] = $existingAttribute['Attribute'][$rF];
                        }
                    }
                    // carry on with adding this attribute - Don't forget! if orgc!=user org, create shadow attribute, not attribute!
                } else {
                    // the old one is newer or the same, replace the request's attribute with the old one
                    throw new MethodNotAllowedException(__('Attribute could not be saved: Attribute in the request not newer than the local copy.'));
                }
            } else {
                if ($this->_isRest() || $this->response->type() === 'application/json') {
                    throw new NotFoundException(__('Invalid attribute.'));
                } else {
                    $this->Flash->error(__('Invalid attribute.'));
                    $this->redirect(array('controller' => 'events', 'action' => 'index'));
                }
            }
            if ($existingAttribute['Attribute']['object_id']) {
                $result = $this->Attribute->save($this->request->data, array('fieldList' => Attribute::EDITABLE_FIELDS));
                if ($result) {
                    $this->Attribute->AttributeTag->handleAttributeTags($this->Auth->user(), $this->request->data['Attribute'], $attribute['Event']['id'], $capture=true);
                    $this->Attribute->Event->captureAnalystData($this->Auth->user(), $this->request->data['Attribute'], 'Attribute', $existingAttribute['Attribute']['uuid']);
                }
                $this->Attribute->Object->updateTimestamp($existingAttribute['Attribute']['object_id']);
            } else {
                $result = $this->Attribute->save($this->request->data, array('fieldList' => Attribute::EDITABLE_FIELDS));
                if ($result) {
                    $this->Attribute->AttributeTag->handleAttributeTags($this->Auth->user(), $this->request->data['Attribute'], $attribute['Event']['id'], $capture=true);
                    $this->Attribute->Event->captureAnalystData($this->Auth->user(), $this->request->data['Attribute'], 'Attribute', $existingAttribute['Attribute']['uuid']);
                }
                if ($this->request->is('ajax')) {
                    $this->autoRender = false;
                    if ($result) {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Attribute updated.')),'status' => 200, 'type' => 'json'));
                    } else {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Could not update attribute, reason: ' . json_encode($this->Attribute->validationErrors))),'status' => 200, 'type' => 'json'));
                    }
                }
            }
            if ($result) {
                $this->Flash->success(__('The attribute has been saved'));
                // remove the published flag from the event
                $this->Attribute->Event->unpublishEvent($eventId, false, $dateObj->getTimestamp());
                if (!empty($this->Attribute->data['Attribute']['object_id'])) {
                    $this->Attribute->Object->updateTimestamp($this->Attribute->data['Attribute']['object_id'], $dateObj->getTimestamp());
                }
                if ($this->_isRest()) {
                  $saved_attribute = $this->Attribute->find('first', array(
                          'conditions' => array('id' => $this->Attribute->id),
                          'recursive' => -1,
                          'contain' => array('AttributeTag' => array('Tag'))
                  ));
                  if ($this->response->type() === 'application/json') {
                      $type = 'json';
                  } else {
                      $type = 'xml';
                  }
                  App::uses(strtoupper($type) . 'ConverterTool', 'Tools');
                  $tool = strtoupper($type) . 'ConverterTool';
                  $converter = new $tool();
                  $saved_attribute = $converter->convertAttribute($saved_attribute, true);
                  return $this->RestResponse->viewData($saved_attribute, $type);
                } else {
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Attributes', 'edit', false, $this->Attribute->validationErrors);
                } else {
                    if (!CakeSession::read('Message.flash')) {
                        $this->Flash->error(__('The attribute could not be saved. Please, try again.'));
                    } else {
                        $this->request->data = $this->Attribute->read(null, $id);
                    }
                }
            }
        } else {
            $this->request->data = $this->Attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $id]
            ]);
        }
        $this->set('attribute', $this->request->data);
        if (!empty($this->request->data['Attribute']['object_id'])) {
            $this->set('objectAttribute', true);
        } else {
            $this->set('objectAttribute', false);
        }
        // enabling / disabling the distribution field in the edit view based on whether user's org == orgc in the event
        $this->set('event', $attribute); // Attribute contains 'Event' field
        // needed for RBAC
        // combobox for types
        $isAttachment = $this->Attribute->typeIsAttachment($attribute['Attribute']['type']);
        $this->set('attachment', $isAttachment);
        if ($isAttachment) {
            $types = [$attribute['Attribute']['type'] => $attribute['Attribute']['type']];
        } else {
            $types = $this->Attribute->getNonAttachmentTypes();
            $types = $this->_arrayToValuesIndexArray($types);
        }
        $this->set('types', $types);
        $this->__common();
        $this->set('title_for_layout', __('Edit attribute'));
        $this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
        $this->set('typeDefinitions', $this->Attribute->typeDefinitions);
        $categoryDefinitions = $this->Attribute->categoryDefinitions;
        $categories = array_keys($categoryDefinitions);
        $categories = $this->_arrayToValuesIndexArray($categories);
        if (!empty($this->request->data['Attribute']['object_id'])) {
            foreach ($categoryDefinitions as $k => $v) {
                if (!in_array($this->request->data['Attribute']['type'], $v['types'])) {
                    unset($categoryDefinitions[$k]);
                }
            }
            foreach ($categories as $k => $v) {
                if (!isset($categoryDefinitions[$k])) {
                    unset($categories[$k]);
                }
            }
        }
        $this->set('categories', $categories);
        $this->set('categoryDefinitions', $categoryDefinitions);
        $this->set('action', $this->action);
        $this->render('add');
    }

    // ajax edit - post a single edited field and this method will attempt to save it and return a json with the validation errors if they occur.
    public function editField($id)
    {
        $attribute = $this->Attribute->fetchAttributeSimple($this->Auth->user(), [
            'conditions' => ['Attribute.id' => $id],
        ]);
        if (empty($attribute)) {
            return new CakeResponse(array('body'=> json_encode(array('fail' => false, 'errors' => 'Invalid attribute')), 'status' => 200, 'type' => 'json'));
        }
        if (!$this->__canModifyEvent($attribute)) {
            return new CakeResponse(array('body' => json_encode(array('fail' => false, 'errors' => 'You do not have permission to do that')), 'status' => 200, 'type' => 'json'));
        }
        if (!$this->_isRest()) {
            $this->Attribute->Event->insertLock($this->Auth->user(), $attribute['Attribute']['event_id']);
        }
        if (empty($this->request->data['Attribute'])) {
            $this->request->data = array('Attribute' => $this->request->data);
            if (empty($this->request->data['Attribute'])) {
                throw new MethodNotAllowedException(__('Invalid input.'));
            }
        }
        $validFields = array('value', 'category', 'type', 'comment', 'to_ids', 'distribution', 'first_seen', 'last_seen');
        $changed = false;
        foreach ($this->request->data['Attribute'] as $changedKey => $changedField) {
            if (!in_array($changedKey, $validFields, true)) {
                throw new MethodNotAllowedException(__('Invalid field.'));
            }
            if ($attribute['Attribute'][$changedKey] == $changedField) {
                return new CakeResponse(array('body'=> json_encode(array('errors'=> array('value' => 'nochange'))), 'status'=>200, 'type' => 'json'));
            }
            $attribute['Attribute'][$changedKey] = $changedField;
            $changed = true;
        }
        if (!$changed) {
            return new CakeResponse(array('body'=> json_encode(array('errors'=> array('value' => 'nochange'))), 'status'=>200, 'type' => 'json'));
        }
        $time = time();
        $attribute['Attribute']['timestamp'] = $time;

        if ($this->Attribute->save($attribute)) {
            $this->Attribute->Event->unpublishEvent($attribute['Attribute']['event_id'], false, $time);

            if ($attribute['Attribute']['object_id'] != 0) {
                $this->Attribute->Object->updateTimestamp($attribute['Attribute']['object_id'], $time);
            }
            return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Field updated.', 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
        } else {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $this->Attribute->validationErrors)), 'status'=>200, 'type' => 'json'));
        }
    }

    public function view($id)
    {
        if ($this->request->is('head')) { // Just check if attribute exists
            $attribute = $this->Attribute->fetchAttributesSimple($this->Auth->user(), [
                'conditions' => $this->__idToConditions($id),
                'fields' => ['Attribute.id'],
            ]);
            return new CakeResponse(['status' => $attribute ? 200 : 404]);
        }

        $attribute = $this->__fetchAttribute($id);
        if (empty($attribute)) {
            throw new MethodNotAllowedException(__('Invalid attribute'));
        }
        if ($this->_isRest()) {
            if (isset($attribute['AttributeTag'])) {
                foreach ($attribute['AttributeTag'] as $k => $tag) {
                    $attribute['Attribute']['Tag'][$k] = $tag['Tag'];
                }
            }
            unset($attribute['Attribute']['value1']);
            unset($attribute['Attribute']['value2']);
            $this->set('Attribute', $attribute['Attribute']);
            $this->set('_serialize', array('Attribute'));
        } else {
            $this->redirect('/events/view/' . $attribute['Attribute']['event_id']);
        }
    }

    public function viewPicture($id, $thumbnail=false)
    {
        $user = $this->_closeSession();
        $conditions = $this->__idToConditions($id);
        $conditions['Attribute.type'] = 'attachment';

        if ($this->_isRest()) {
            $options = array(
                'conditions' => $conditions,
                'includeAllTags' => false,
                'includeAttributeUuid' => true,
                'flatten' => true,
                'deleted' => [0, 1],
                'withAttachments' => true,
            );
            $attribute = $this->Attribute->fetchAttributes($user, $options);
            if (empty($attribute)) {
                throw new MethodNotAllowedException('Invalid attribute');
            }
            $attribute = $attribute[0];
            if (!$this->Attribute->isImage($attribute['Attribute'])) {
                throw new NotFoundException("Attribute is not an image.");
            }
            return $this->RestResponse->viewData($attribute['Attribute']['data'], $this->response->type());
        }

        $attribute = $this->Attribute->fetchAttributeSimple($user, [
            'conditions' => $conditions,
            'fields' => ['Attribute.id', 'Attribute.event_id', 'Attribute.type', 'Attribute.value'],
        ]);
        if (empty($attribute)) {
            throw new MethodNotAllowedException('Invalid attribute');
        }
        if (!$this->Attribute->isImage($attribute['Attribute'])) {
            throw new NotFoundException("Attribute is not an image.");
        }

        if ($thumbnail) {
            $extension = $thumbnail === 'webp' ? 'webp' : 'png';
            $maxWidth = $this->request->params['named']['width'] ?? null;
            $maxHeight = $this->request->params['named']['height'] ?? null;
            $imageData = $this->Attribute->getThumbnail($attribute, $extension, $maxWidth, $maxHeight);
        } else {
            $imageData = $this->Attribute->getPictureData($attribute);
            $extension = strtolower(pathinfo($attribute['Attribute']['value'], PATHINFO_EXTENSION));
        }

        if ($imageData instanceof File) {
            return $this->RestResponse->sendFile($imageData, $extension);
        }

        $this->response->body($imageData);
        $this->response->type($extension);
        return $this->response;
    }

    public function delete($id, $hard = false)
    {
        if (isset($this->params['named']['hard'])) {
            $hard = $this->params['named']['hard'];
        }
        if (isset($this->request->data['hard'])) {
            $hard = $this->request->data['hard'];
        }

        $conditions = $this->__idToConditions($id);
        if (!$hard) {
            $conditions['deleted'] = 0;
        }
        $attribute = $this->Attribute->find('first', array(
                'conditions' => $conditions,
                'recursive' => -1,
                'fields' => array('id', 'event_id'),
        ));
        if (empty($attribute)) {
            throw new NotFoundException('Invalid attribute');
        }
        $this->set('id', $attribute['Attribute']['id']);
        if ($this->request->is('ajax')) {
            if ($this->request->is('post')) {
                if ($this->Attribute->deleteAttribute($attribute['Attribute']['id'], $this->Auth->user(), $hard)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Attribute deleted.')), 'status'=>200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Attribute was not deleted.')), 'status'=>200, 'type' => 'json'));
                }
            } else {
                $this->set('hard', $hard);
                $this->set('event_id', $attribute['Attribute']['event_id']);
                $this->render('ajax/attributeConfirmationForm');
            }
        } else {
            if (!$this->request->is('post') && !$this->request->is('delete')) {
                throw new MethodNotAllowedException(__('This function is only accessible via POST requests.'));
            }
            if ($this->Attribute->deleteAttribute($attribute['Attribute']['id'], $this->Auth->user(), $hard)) {
                if ($this->_isRest() || $this->response->type() === 'application/json') {
                    $this->set('message', 'Attribute deleted.');
                    $this->set('_serialize', array('message'));
                } else {
                    $this->Flash->success(__('Attribute deleted'));
                    $this->redirect($this->referer());
                }
            } else {
                if ($this->_isRest() || $this->response->type() === 'application/json') {
                    throw new Exception(__('Attribute was not deleted'));
                } else {
                    $this->Flash->error(__('Attribute was not deleted'));
                    $this->redirect(array('action' => 'index'));
                }
                $this->Flash->success(__('Attribute deleted'));
            }
        }
    }

    public function restore($id = null)
    {
        $attribute = $this->Attribute->find('first', array(
                'conditions' => array('Attribute.id' => $id),
                'recursive' => -1,
                'fields' => array('Attribute.id', 'Attribute.event_id'),
                'contain' => array(
                    'Event' => array(
                        'fields' => array('Event.orgc_id')
                    )
                )
        ));
        if (empty($attribute) || !$this->__canModifyEvent($attribute)) {
            if ($this->request->is('ajax')) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Attribute')), 'type' => 'json', 'status'=>200));
            } else {
                throw new MethodNotAllowedException(__('Invalid Attribute'));
            }
        }
        if (!$this->_isRest()) {
            $this->Attribute->Event->insertLock($this->Auth->user(), $attribute['Attribute']['event_id']);
        }
        if ($this->request->is('ajax')) {
            if ($this->request->is('post')) {
                $result = $this->Attribute->restore($id, $this->Auth->user());
                if ($result === true) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Attribute restored.')), 'type' => 'json' ,'status'=>200));
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $result)), 'type' => 'json', 'status'=>200));
                }
            } else {
                $this->set('id', $id);
                $this->set('event_id', $attribute['Attribute']['event_id']);
                $this->render('ajax/attributeRestorationForm');
            }
        } else {
            if (!$this->request->is('post') && !$this->_isRest()) {
                throw new MethodNotAllowedException();
            }
            if ($this->Attribute->restore($id, $this->Auth->user())) {
                $this->redirect(array('action' => 'view', $id));
            } else {
                throw new NotFoundException(__('Could not restore the attribute'));
            }
        }
    }

    public function deleteSelected($eventId = false, $hard = false)
    {
        if ($this->request->is('get')) {
            return $this->RestResponse->describe('Attributes', 'deleteSelected', false, $this->response->type());
        } else if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This function is only accessible via POST requests.'));
        }
        // get a json object with a list of attribute IDs to be deleted
        // check each of them and return a json object with the successful deletes and the failed ones.
        if ($this->_isRest()) {
            if (empty($this->request->data['Attribute'])) {
                $this->request->data['Attribute'] = $this->request->data;
            }
            if (isset($this->request->data['Attribute']['id'])) {
                $ids = $this->request->data['Attribute']['id'];
            } else {
                $ids = $this->request->data['Attribute'];
            }
            if (empty($eventId) && isset($this->request->data['Attribute']['event_id']) && is_numeric($this->request->data['Attribute']['event_id'])) {
                $eventId = $this->request->data['Attribute']['event_id'];
            }
        } else {
            $ids = $this->_jsonDecode($this->request->data['Attribute']['ids_delete']);
        }
        if (empty($ids)) {
            throw new NotFoundException(__('No matching attributes found.'));
        }
        if (empty($eventId)) {
            throw new MethodNotAllowedException(__('No event ID set.'));
        }
        if (!$this->_isSiteAdmin()) {
            $event = $this->Attribute->Event->find('first', [
                'conditions' => ['id' => $eventId],
                'recursive' => -1,
                'fields' => ['id', 'orgc_id', 'user_id'],
            ]);
            if (!$event) {
                throw new NotFoundException(__('Invalid event'));
            }
            if (!$this->__canModifyEvent($event)) {
                throw new ForbiddenException(__('You do not have permission to do that.'));
            }
        }
        $conditions = ['id' => $ids, 'event_id' => $eventId];
        if ($ids === 'all') {
            unset($conditions['id']);
        }
        if ($hard || ($this->_isRest() && empty($this->request->data['Attribute']['allow_hard_delete']))) {
            $conditions['deleted'] = 0;
        }
        // find all attributes from the ID list that also match the provided event ID.
        $attributes = $this->Attribute->find('list', [
            'conditions' => $conditions,
            'fields' => ['id', 'deleted'],
        ]);
        if (empty($attributes)) {
            throw new NotFoundException(__('No matching attributes found.'));
        }
        if ($ids === 'all') {
            $ids = array_keys($attributes);
        }
        $user = $this->_closeSession();
        $successes = [];
        foreach ($attributes as $attributeId => $deleted) {
            if ($this->Attribute->deleteAttribute($attributeId, $user, $hard || $deleted == 1)) {
                $successes[] = $attributeId;
            }
        }
        $fails = array_diff($ids, $successes);
        if (empty($fails) && count($successes) > 0) {
            $message = __n('%s attribute deleted.', '%s attributes deleted', count($successes), count($successes));
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('Attributes', 'deleteSelected', $eventId, false, $message);
            }
            return $this->RestResponse->viewData(['saved' => true, 'success' => $message], 'json');
        } else {
            $message = count($successes) . ' attribute' . (count($successes) != 1 ? 's' : '') . ' deleted, but ' . count($fails) . ' attribute' . (count($fails) != 1 ? 's' : '') . ' could not be deleted.';
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Attributes', 'deleteSelected', false, $message);
            }
            return $this->RestResponse->viewData(['saved' => false, 'errors' => $message], 'json');
        }
    }

    public function getMassEditForm($eventId)
    {
        if (!$this->request->is('ajax') || !$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This method can only be accessed via AJAX and POST.'));
        }
        if (!isset($eventId)) {
            throw new MethodNotAllowedException(__('No event ID provided.'));
        }
        $event = $this->Attribute->Event->fetchSimpleEvent($this->Auth->user(), $eventId, array(
            'fields' => array('id', 'orgc_id', 'org_id', 'user_id', 'published', 'timestamp')
        ));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You are not authorized to edit this event.'));
        }
        $selectedAttributeIds = $this->_jsonDecode($this->request->data['selected_ids']);
        if (empty($selectedAttributeIds)) {
            throw new MethodNotAllowedException(__('No attributes selected'));
        }

        $attributes = $this->Attribute->fetchAttributes($this->Auth->user(), [
            'conditions' => ['Attribute.id' => $selectedAttributeIds, 'Attribute.event_id' => $event['Event']['id']],
            'flatten' => true,
        ]);

        // tags to remove
        $tags = $this->Attribute->AttributeTag->getAttributesTags($attributes);
        $tagItemsRemove = array();
        foreach ($tags as $tag) {
            $tagName = $tag['name'];
            $tagItemsRemove[] = array(
                'name' => $tagName,
                'value' => $tag['id'],
                'template' => array(
                    'name' => array(
                        'name' => $tagName,
                        'label' => array(
                            'background' => isset($tag['colour']) ? $tag['colour'] : '#ffffff'
                        )
                    ),
                )
            );
        }
        unset($tags);

        // clusters to remove
        $clusters = $this->Attribute->AttributeTag->getAttributesClusters($this->Auth->user(), $attributes);
        $clusterItemsRemove = array();
        foreach ($clusters as $cluster) {
            $name = $cluster['value'];
            $optionName = $cluster['value'];
            $synom = $cluster['synonyms_string'] !== '' ? " ({$cluster['synonyms_string']})" : '';
            $optionName .= $synom;

            $temp = array(
                'name' => $optionName,
                'value' => $cluster['id'],
                'template' => array(
                    'name' => $name,
                    'infoExtra' => $cluster['description']
                )
            );
            if ($cluster['synonyms_string'] !== '') {
                $temp['infoContextual'] = __('Synonyms: ') . $cluster['synonyms_string'];
            }
            $clusterItemsRemove[] = $temp;
        }

        // clusters to add
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $clusters = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array(
            'fields' => array('value', 'id'),
            'conditions' => array('published' => true)
        ));
        $clusterItemsAdd = array();
        foreach ($clusters as $cluster) {
            $clusterItemsAdd[] = array(
                'name' => $cluster['GalaxyCluster']['value'],
                'value' => $cluster['GalaxyCluster']['id']
            );
        }

        $tags = $this->Attribute->AttributeTag->Tag->fetchUsableTags($this->Auth->user(), false);
        $tagItemsAdd = array();
        foreach ($tags as $tag) {
            $tagName = $tag['Tag']['name'];
            $tagItemsAdd[] = array(
                'name' => $tagName,
                'value' => $tag['Tag']['id'],
                'template' => array(
                    'name' => array(
                        'name' => $tagName,
                        'label' => array(
                            'background' => isset($tag['Tag']['colour']) ? $tag['Tag']['colour'] : '#ffffff'
                        )
                    ),
                )

            );
        }

        $this->layout = false;
        $this->set('id', $eventId);
        $this->set('selectedAttributeIds', $selectedAttributeIds);
        $this->set('sgs', $this->Attribute->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', true));
        $this->set('distributionLevels', $this->Attribute->distributionLevels);
        $this->set('distributionDescriptions', $this->Attribute->distributionDescriptions);
        $this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
        $this->set('tagItemsRemove', $tagItemsRemove);
        $this->set('tagItemsAdd', $tagItemsAdd);
        $this->set('clusterItemsAdd', $clusterItemsAdd);
        $this->set('clusterItemsRemove', $clusterItemsRemove);
        $this->set('options', array( // set chosen (select picker) options
            'multiple' => -1,
            'autofocus' => false,
            'disabledSubmitButton' => true,
            'flag_redraw_chosen' => true,
            'select_options' => array(
                'additionalData' => array(
                    'event_id' => $eventId,
                ),
            ),
        ));
        $this->render('ajax/attributeEditMassForm');
    }

    public function editSelected($eventId)
    {
        $this->request->allowMethod(['post']);

        $event = $this->Attribute->Event->find('first', array(
            'conditions' => array('id' => $eventId),
            'recursive' => -1,
            'fields' => array('id', 'orgc_id', 'org_id', 'user_id', 'published', 'timestamp', 'uuid')
        ));
        if (!$event) {
            throw new NotFoundException(__('Invalid event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You are not authorized to edit this event.'));
        }

        $requestData = $this->request->data['Attribute'];
        $attribute_ids = $this->_jsonDecode($requestData['attribute_ids']);
        $attributes = $this->Attribute->find('all', array(
            'conditions' => array(
                'id' => $attribute_ids,
                'event_id' => $eventId,
            ),
            'recursive' => -1,
        ));

        $tags_ids_remove = json_decode($requestData['tags_ids_remove']);
        $tags_ids_add = json_decode($requestData['tags_ids_add']);
        $clusters_ids_remove = json_decode($requestData['clusters_ids_remove']);
        $clusters_ids_add = json_decode($requestData['clusters_ids_add']);
        $changeInTagOrCluster = ($tags_ids_remove !== null && count($tags_ids_remove) > 0)
            || ($tags_ids_add === null || count($tags_ids_add) > 0)
            || ($clusters_ids_remove === null || count($clusters_ids_remove) > 0)
            || ($clusters_ids_add === null || count($clusters_ids_add) > 0);

        $changeInAttribute = ($requestData['to_ids'] != 2) || ($requestData['distribution'] != 6) || ($requestData['comment'] != null) || ($requestData['disable_correlation'] != 2);

        if (!$changeInAttribute && !$changeInTagOrCluster) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status' => 200, 'type' => 'json'));
        }

        if ($requestData['to_ids'] != 2) {
            $toIds = $requestData['to_ids'] == 0 ? false : true;
            foreach ($attributes as $key => $attribute) {
                $attributes[$key]['Attribute']['to_ids'] = $toIds;
            }
        }

        if ($requestData['distribution'] != 6) {
            foreach ($attributes as $key => $attribute) {
                $attributes[$key]['Attribute']['distribution'] = $requestData['distribution'];
            }
            if ($requestData['distribution'] == 4) {
                $sharingGroupId = $requestData['sharing_group_id'];
                if (!$this->__canUseSharingGroup($sharingGroupId)) {
                    throw new ForbiddenException(__('Invalid Sharing Group or not authorised.'));
                }

                foreach ($attributes as $key => $attribute) {
                    $attributes[$key]['Attribute']['sharing_group_id'] = $sharingGroupId;
                }
            } else {
                foreach ($attributes as $key => $attribute) {
                    $attributes[$key]['Attribute']['sharing_group_id'] = 0;
                }
            }
        }

        if ($requestData['comment'] != null) {
            foreach ($attributes as $key => $attribute) {
                $attributes[$key]['Attribute']['comment'] = $requestData['comment'];
            }
        }

        if ($requestData['disable_correlation'] != 2) {
            $disableCorrelation = $requestData['disable_correlation'] === '0' ? false : true;
            foreach ($attributes as $key => $attribute) {
                $attributes[$key]['Attribute']['disable_correlation'] = $disableCorrelation;
            }
        }

        $timestamp = time();
        foreach ($attributes as $key => $attribute) {
            $attributes[$key]['Attribute']['timestamp'] = $timestamp;
        }

        if ($changeInAttribute) {
            if ($requestData['is_proposal']) { // create ShadowAttributes instead
                $shadowAttributes = array();
                foreach ($attributes as $attribute) {
                    $shadowAttribute['ShadowAttribute'] = $attribute['Attribute'];
                    unset($shadowAttribute['ShadowAttribute']['id']);
                    $shadowAttribute['ShadowAttribute']['email'] = $this->Auth->user('email');
                    $shadowAttribute['ShadowAttribute']['org_id'] = $this->Auth->user('org_id');
                    $shadowAttribute['ShadowAttribute']['event_uuid'] = $event['Event']['uuid'];
                    $shadowAttribute['ShadowAttribute']['event_org_id'] = $event['Event']['org_id'];
                    $shadowAttribute['ShadowAttribute']['old_id'] = $attribute['Attribute']['id'];
                    $shadowAttributes[] = $shadowAttribute;
                }
                $saveSuccess = $this->Attribute->Event->ShadowAttribute->saveMany($shadowAttributes);
            } else {
                $saveSuccess = $this->Attribute->saveMany($attributes);
            }
            if ($saveSuccess) {
                if (!$this->_isRest()) {
                    $this->Attribute->Event->insertLock($this->Auth->user(), $event['Event']['id']);
                }
                $this->Attribute->Event->unpublishEvent($event, false, $timestamp);
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'validationErrors' => $this->Attribute->validationErrors)), 'status' => 200, 'type' => 'json'));
            }
        }

        // apply changes in tag/cluster
        foreach ($attributes as $attribute) {
            foreach ($tags_ids_remove as $tag_id) {
                $this->removeTag($attribute['Attribute']['id'], $tag_id);
            }
            foreach ($tags_ids_add as $tag_id) {
                $this->addTag($attribute['Attribute']['id'], $tag_id);
            }
            $this->Galaxy = ClassRegistry::init('Galaxy');
            foreach ($clusters_ids_remove as $cluster_id) {
                $this->Galaxy->detachCluster($this->Auth->user(), 'attribute', $attribute['Attribute']['id'], $cluster_id);
            }
            foreach ($clusters_ids_add as $cluster_id) {
                $this->Galaxy->attachCluster($this->Auth->user(), 'attribute', $attribute['Attribute']['id'], $cluster_id);
            }
        }

        return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status' => 200, 'type' => 'json'));
    }

    private function __getSearchFilters(&$exception)
    {
        if (isset($this->request->data['Attribute'])) {
            $this->request->data = $this->request->data['Attribute'];
        }
        $checkForEmpty = array('value', 'tags', 'uuid', 'org', 'type', 'category', 'first_seen', 'last_seen');
        foreach ($checkForEmpty as $field) {
            if (empty($this->request->data[$field]) || $this->request->data[$field] === 'ALL') {
                unset($this->request->data[$field]);
            }
        }
        if (empty($this->request->data['to_ids'])) {
            unset($this->request->data['to_ids']);
            $this->request->data['ignore'] = 1;
        }
        $paramArray = array('value' , 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted', 'includeEventUuid', 'event_timestamp', 'threat_level_id', 'includeEventTags', 'first_seen', 'last_seen');
        $filterData = array(
            'request' => $this->request,
            'named_params' => $this->request->params['named'],
            'paramArray' => $paramArray,
            'additional_delimiters' => PHP_EOL
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception);
        if (!empty($filters['uuid'])) {
            if (!is_array($filters['uuid'])) {
                $filters['uuid'] = array($filters['uuid']);
            }
            $uuid = array();
            $ids = array();
            foreach ($filters['uuid'] as $k => $filter) {
                if ($filter[0] === '!') {
                    $filter = substr($filter, 1);
                }
                if (Validation::uuid($filter)) {
                    $uuid[] = $filters['uuid'][$k];
                } else {
                    $ids[] = $filters['uuid'][$k];
                }
            }
            if (empty($uuid)) {
                unset($filters['uuid']);
            } else {
                $filters['uuid'] = $uuid;
            }
            if (!empty($ids)) {
                $filters['eventid'] = $ids;
            }
        }
        return $filters;
    }

    public function search($continue = false)
    {
        $user = $this->Auth->user();
        $exception = null;
        $filters = $this->__getSearchFilters($exception);
        $this->set('passedArgsArray', ['results' => $continue]);
        if ($this->request->is('post') || !empty($this->request->params['named']['tags'])) {
            if ($filters === false) {
                return $exception;
            }
            $this->Session->write('search_attributes_filters', json_encode($filters));
        } elseif ($continue === 'results') {
            $filters = $this->Session->read('search_attributes_filters');
            $filters = empty($filters) ? [] : $this->_jsonDecode($filters);
        } else {
            $types = $this->_arrayToValuesIndexArray(array_keys($this->Attribute->typeDefinitions));
            ksort($types);
            $this->set('types', array_merge(['ALL' => 'ALL'], $types));
            // combobox for categories
            $categories = array_merge(['ALL' => 'ALL'], $this->_arrayToValuesIndexArray(array_keys($this->Attribute->categoryDefinitions)));
            $this->set('categories', $categories);

            $categoryDefinition = $this->Attribute->categoryDefinitions;
            $categoryDefinition = array_merge(["ALL" => ['types' => array_keys($this->Attribute->typeDefinitions), 'formdesc' => '']], $categoryDefinition);
            foreach ($categoryDefinition as &$def) {
                $def['types'] = array_merge(['ALL'], $def['types']);
            }
            $this->set('categoryDefinitions', $categoryDefinition);
            $this->set('typeDefinitions', $this->Attribute->typeDefinitions);
            $this->set('fieldDesc', $this->__fieldDesc());

            $this->Session->write('search_attributes_filters', null);
        }
        if (!empty($filters)) {
            $filters['includeCorrelations'] = 1;
            $params = $this->Attribute->restSearch($user, 'json', $filters, true);
            if (!isset($params['conditions']['Attribute.deleted'])) {
                $params['conditions']['Attribute.deleted'] = 0;
            }

            // Force index for performance reasons see #3321
            if (isset($filters['value'])) {
                $this->paginate['forceIndexHint'] = 'value1, value2';
            }

            $this->paginate['conditions'] = $params['conditions'];
            $this->paginate['ignoreIndexHint'] = 'deleted';
            $attributes = $this->paginate();
            $this->Attribute->attachTagsToAttributes($attributes, ['includeAllTags' => true]);

            $orgTable = $this->Attribute->Event->Orgc->find('all', [
                'fields' => ['Orgc.id', 'Orgc.name', 'Orgc.uuid'],
            ]);
            $orgTable = array_column(array_column($orgTable, 'Orgc'), null, 'id');
            $sgids = $this->Attribute->SharingGroup->authorizedIds($user);
            foreach ($attributes as &$attribute) {
                if (isset($orgTable[$attribute['Event']['orgc_id']])) {
                    $attribute['Event']['Orgc'] = $orgTable[$attribute['Event']['orgc_id']];
                }
                if (isset($orgTable[$attribute['Event']['org_id']])) {
                    $attribute['Event']['Org'] = $orgTable[$attribute['Event']['org_id']];
                }
                if (isset($filters['includeCorrelations'])) {
                    $temp = $this->Attribute->Correlation->getRelatedAttributes(
                        $user,
                        $sgids,
                        $attribute['Attribute'],
                        [],
                        true
                    );
                    foreach ($temp as &$t) {
                        $t['info'] = $t['Event']['info'];
                        $t['org_id'] = $t['Event']['org_id'];
                        $t['date'] = $t['Event']['date'];
                    }
                    $attribute['Event']['RelatedAttribute'][$attribute['Attribute']['id']] = $temp;
                }
            }
            if ($this->_isRest()) {
                return $this->RestResponse->viewData($attributes, $this->response->type());
            }

            list($attributes, $sightingsData) = $this->__searchUI($attributes, $user);
            $this->set('sightingsData', $sightingsData);

            if (isset($filters['tags']) && !empty($filters['tags'])) {
                // if the tag is passed by ID - show its name in the view
                $this->loadModel('Tag');
                if (!is_array($filters['tags'])) {
                    $filters['tags'] = array($filters['tags']);
                }
                foreach ($filters['tags'] as &$v) {
                    if (!is_numeric($v))
                        continue;
                    $tag = $this->Tag->find('first', [
                        'conditions' => ['Tag.id' => $v],
                        'fields' => ['name'],
                        'recursive' => -1
                        ]);
                    if (!empty($tag)) {
                        $v = $tag['Tag']['name'];
                    }
                }
            }
            $this->set('orgTable', array_column($orgTable, 'name', 'id'));
            $this->set('filters', $filters);
            $this->set('attributes', $attributes);
            $this->set('isSearch', 1);
            $this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
            $this->set('shortDist', $this->Attribute->shortDist);
            $this->set('distributionLevels', $this->Attribute->distributionLevels);
            $this->render('index');
        }
        if (isset($attributeTags)) {
            $this->set('attributeTags', $attributeTags);
        }
    }

    /**
     * @param array $attributes
     * @param array $user
     * @return array|array[]
     */
    private function __searchUI(array $attributes, array $user)
    {
        if (empty($attributes)) {
            return [[], []];
        }

        $this->Feed = ClassRegistry::init('Feed');

        $this->loadModel('Sighting');
        $this->loadModel('AttachmentScan');
        $galaxyTags = [];
        foreach ($attributes as &$attribute) {
            if ($this->Attribute->isImage($attribute['Attribute'])) {
                if (extension_loaded('gd')) {
                    // if extension is loaded, the data is not passed to the view because it is asynchronously fetched
                    $attribute['Attribute']['image'] = true; // tell the view that it is an image despite not having the actual data
                } else {
                    $attribute['Attribute']['image'] = $this->Attribute->base64EncodeAttachment($attribute['Attribute']);
                }
            }
            if ($attribute['Attribute']['type'] === 'attachment' && $this->AttachmentScan->isEnabled()) {
                $infected = $this->AttachmentScan->isInfected(AttachmentScan::TYPE_ATTRIBUTE, $attribute['Attribute']['id']);
                $attribute['Attribute']['infected'] = $infected;
            }

            if ($attribute['Attribute']['distribution'] == 4) {
                $attribute['Attribute']['SharingGroup'] = $attribute['SharingGroup'];
            }

            $attribute['Attribute']['AttributeTag'] = $attribute['AttributeTag'];
            foreach ($attribute['Attribute']['AttributeTag'] as $at) {
                if ($at['Tag']['is_galaxy']) {
                    $galaxyTags[$at['Tag']['id']] = $at['Tag']['name'];
                }
            }
            unset($attribute['AttributeTag']);
        }
        unset($attribute);

        // Fetch galaxy clusters in one query
        if (!empty($galaxyTags)) {
            $this->loadModel('GalaxyCluster');
            $clusters = $this->GalaxyCluster->getClustersByTags($galaxyTags, $user, true, false);
            $clusters = array_column(array_column($clusters, 'GalaxyCluster'), null, 'tag_id');
        } else {
            $clusters = [];
        }

        // `attachFeedCorrelations` method expects different attribute format, so we need to transform that, then process
        // and then take information back to original attribute structure.
        $fakeEventArray = [];
        $attributesWithFeedCorrelations = $this->Feed->attachFeedCorrelations(array_column($attributes, 'Attribute'), $user, $fakeEventArray);

        foreach ($attributes as $k => $attribute) {
            // Assign galaxies
            $galaxies = [];
            foreach ($attribute['Attribute']['AttributeTag'] as $k2 => $attributeTag) {
                if (!isset($clusters[$attributeTag['Tag']['id']])) {
                    continue;
                }
                $cluster = $clusters[$attributeTag['Tag']['id']];
                $galaxyId = $cluster['Galaxy']['id'];
                $cluster['local'] = $attributeTag['local'] ?? false;
                $cluster['attribute_tag_id'] = $attributeTag['id'];
                if (isset($attribute['Attribute']['Galaxy'][$galaxyId])) {
                    unset($cluster['Galaxy']);
                    $galaxies[$galaxyId]['GalaxyCluster'][] = $cluster;
                } else {
                    $galaxies[$galaxyId] = $cluster['Galaxy'];
                    unset($cluster['Galaxy']);
                    $galaxies[$galaxyId]['GalaxyCluster'] = [$cluster];
                }
                unset($attributes[$k]['Attribute']['AttributeTag'][$k2]); // remove galaxy tag
            }
            $attributes[$k]['Attribute']['Galaxy'] = array_values($galaxies);

            if (isset($attributesWithFeedCorrelations[$k]['Feed'])) {
                $attributes[$k]['Attribute']['Feed'] = $attributesWithFeedCorrelations[$k]['Feed'];
            }
        }
        $sightingsData = $this->Sighting->attributesStatistics($attributes, $user);
        return [$attributes, $sightingsData];
    }

    public function checkComposites()
    {
        if (!self::_isAdmin()) {
            throw new NotFoundException();
        }
        $this->set('fails', $this->Attribute->checkComposites());
    }

    public function downloadAttachment($key='download', $id)
    {
        if ($key != null && $key != 'download') {
            $user = $this->_checkAuthUser($key);
        } else {
            if (!$this->Auth->user()) {
                throw new UnauthorizedException(__('You are not authorized. Please send the Authorization header with your auth key along with an Accept header for application/xml.'));
            }
            $user = $this->Auth->user();
        }
        // if the user is authorised to use the api key then user will be populated with the user's account
        // in addition we also set a flag indicating whether the user is a site admin or not.
        if (!$user) {
            throw new UnauthorizedException(__('This authentication key is not authorized to be used for exports. Contact your administrator.'));
        }
        $conditions = $this->__idToConditions($id);
        $conditions['Attribute.type'] = array('attachment', 'malware-sample');
        $attributes = $this->Attribute->fetchAttributes($user, array('conditions' => $conditions, 'flatten' => true));
        if (empty($attributes)) {
            throw new UnauthorizedException(__('Attribute does not exist or you do not have the permission to download this attribute.'));
        }
        return $this->__downloadAttachment($attributes[0]['Attribute']);
    }

    // returns an XML with attributes that belong to an event. The type of attributes to be returned can be restricted by type using the 3rd parameter.
    // Similar to the restSearch, this parameter can be chained with '&&' and negations are accepted too. For example filename&&!filename|md5 would return all filenames that don't have an md5
    // The usage of returnAttributes is the following: [MISP-url]/attributes/returnAttributes/<API-key>/<event_id>/<type>/<signature flag>
    // The signature flag is off by default, enabling it will only return attributes that have the to_ids flag set to true.
    public function returnAttributes()
    {
        //$key='download', $id, $type = null, $sigOnly = false
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'id', 'type', 'sigOnly'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args(),
            'injectedParams' => array(
                'returnFormat' => 'xml'
            ),
            'alias' => array(
                'id' => 'eventid'
            )
        ));
        if (!empty($this->_legacyParams['sigOnly'])) {
            $this->_legacyParams['to_ids'] = 1;
        } else {
            $this->_legacyParams['to_ids'] = [0,1];
        }
        if (!empty($this->_legacyParams['type']) && $this->_legacyParams['type'] === 'all') {
            unset($this->_legacyParams['type']);
        }
        if (!empty($this->_legacyParams['type']) && $this->_legacyParams['type'] === 'all') {
            unset($this->_legacyParams['type']);
        }
        if ($this->response->type() === 'application/json') {
            $this->_legacyParams['returnFormat'] = 'json';
        }
        return $this->restSearch();
    }

    public function text()
    {
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'type', 'tags', 'eventId', 'allowNonIDS', 'from', 'to', 'last', 'enforceWarninglist', 'allowNotPublished'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args(),
            'injectedParams' => array(
                'returnFormat' => 'text'
            ),
            'alias' => array(
                'eventId' => 'eventid'
            )
        ));
        if (!empty($this->_legacyParams['allowNonIDS'])) {
            $this->_legacyParams['to_ids'] = [0,1];
        }
        if (!empty($this->_legacyParams['allowNotPublished'])) {
            $this->_legacyParams['published'] = [0,1];
        }
        if (!empty($this->_legacyParams['type']) && $this->_legacyParams['type'] === 'all') {
            unset($this->_legacyParams['type']);
        }
        return $this->restSearch();
    }

    public function rpz()
    {
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'tags', 'eventid', 'from', 'to', 'policy', 'walled_garden', 'ns',
                'email', 'serial', 'refresh', 'retry', 'expiry', 'minimum_ttl', 'ttl',
                'enforceWarninglist', 'ns_alt'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args(),
            'injectedParams' => array(
                'returnFormat' => 'rpz'
            )
        ));
        return $this->restSearch();
    }

    public function bro($key = 'download', $type = 'all', $tags = false, $eventId = false, $from = false, $to = false, $last = false, $enforceWarninglist = false)
    {
        if ($this->request->is('post')) {
            if ($this->request->input('json_decode', true)) {
                $data = $this->request->input('json_decode', true);
            } else {
                $data = $this->request->data;
            }
            if (!empty($data) && !isset($data['request'])) {
                $data = array('request' => $data);
            }
            $paramArray = array('type', 'tags', 'eventId', 'from', 'to', 'last', 'enforceWarninglist');
            foreach ($paramArray as $p) {
                if (isset($data['request'][$p])) {
                    ${$p} = $data['request'][$p];
                }
            }
        }
        $simpleFalse = array('type', 'tags', 'eventId', 'from', 'to', 'last', 'enforceWarninglist');
        foreach ($simpleFalse as $sF) {
            if (!is_array(${$sF}) && (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false')) {
                ${$sF} = false;
            }
        }
        if ($type === 'null' || $type === '0' || $type === 'false') {
            $type = 'all';
        }
        if ($from) {
            $from = $this->Attribute->Event->dateFieldCheck($from);
        }
        if ($to) {
            $to = $this->Attribute->Event->dateFieldCheck($to);
        }
        if ($last) {
            $last = $this->Attribute->Event->resolveTimeDelta($last);
        }
        if ($key != 'download') {
            // check if the key is valid -> search for users based on key
            $user = $this->_checkAuthUser($key);
            if (!$user) {
                throw new UnauthorizedException(__('This authentication key is not authorized to be used for exports. Contact your administrator.'));
            }
        } else {
            if (!$this->Auth->user('id')) {
                throw new UnauthorizedException(__('You have to be logged in to do that.'));
            }
        }
        $filename = 'misp.' . $type . '.intel';
        if ($eventId) {
            $filename = 'misp.' . $type . '.event_' . $eventId . '.intel';
        }
        $responseFile = implode(PHP_EOL, $this->Attribute->bro($this->Auth->user(), $type, $tags, $eventId, $from, $to, $last, $enforceWarninglist)) . PHP_EOL;
        $this->response->body($responseFile);
        $this->response->type('txt');
        $this->response->download($filename);
        return $this->response;
    }

    public function reportValidationIssuesAttributes($eventId = false)
    {
        // search for validation problems in the attributes
        $this->set('result', iterator_to_array($this->Attribute->reportValidationIssuesAttributes($eventId)));
    }

    public function generateCorrelation()
    {
        if ($this->request->is('post')) {
            if (!Configure::read('MISP.background_jobs')) {
                $k = $this->Attribute->Correlation->generateCorrelation();
                $message = __('All done. %s attributes processed.', $k);
                if ($this->_isRest()) {
                    return $this->RestResponse->successResponse(0, $message);
                }

                $this->Flash->success($message);
                $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
            } else {
                /** @var Job $job */
                $job = ClassRegistry::init('Job');
                $jobId = $job->createJob(
                    'SYSTEM',
                    Job::WORKER_DEFAULT,
                    'generate correlation',
                    'All attributes',
                    'Job created.'
                );

                $this->Attribute->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::DEFAULT_QUEUE,
                    BackgroundJobsTool::CMD_ADMIN,
                    [
                        'jobGenerateCorrelation',
                        $jobId
                    ],
                    true,
                    $jobId
                );

                $this->Flash->success(__('Job queued. You can view the progress if you navigate to the active jobs view (Administration -> Jobs).'));
                $this->redirect(Router::url($this->referer(), true));
            }
        } else {
            $this->render('ajax/recorrelationConfirmation');
        }
    }

    public function fetchViewValue($id, $field = null)
    {
        $user = $this->_closeSession();
        $validFields = ['value', 'comment', 'type', 'category', 'distribution', 'timestamp', 'first_seen', 'last_seen'];
        if (!isset($field) || !in_array($field, $validFields, true)) {
            throw new MethodNotAllowedException(__('Invalid field requested.'));
        }
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This function can only be accessed via AJAX.'));
        }

        $fieldsToFetch = ['id', $field];
        if ($field === 'value') {
            $fieldsToFetch[] = 'to_ids'; // for warninglist
            $fieldsToFetch[] = 'type'; // for view
            $fieldsToFetch[] = 'category'; // for view
        }

        $params = array(
            'conditions' => array('Attribute.id' => $id),
            'fields' => $fieldsToFetch,
            'contain' => ['Event'],
            'flatten' => 1,
        );
        $attribute = $this->Attribute->fetchAttributes($user, $params);
        if (empty($attribute)) {
            throw new NotFoundException(__('Invalid attribute'));
        }
        $attribute = $attribute[0];
        $result = $attribute['Attribute'][$field];
        if ($field === 'distribution') {
            $this->set('shortDist', $this->Attribute->shortDist);
        } elseif ($field === 'value') {
            $this->loadModel('Warninglist');
            $attribute['Attribute'] = $this->Warninglist->checkForWarning($attribute['Attribute']);
        }

        $this->set('value', $result);
        $this->set('object', $attribute);
        $this->set('field', $field);
        $this->layout = false;
        $this->render('ajax/attributeViewFieldForm');
    }

    public function fetchEditForm($id, $field = null)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This function can only be accessed via AJAX.'));
        }

        $validFields = array('value', 'comment', 'type', 'category', 'to_ids', 'distribution', 'first_seen', 'last_seen');
        if (!isset($field) || !in_array($field, $validFields, true)) {
            throw new NotFoundException(__('Invalid field requested.'));
        }
        $fieldsToFetch = array('id', 'event_id');
        if ($field === 'category' || $field === 'type') {
            $fieldsToFetch[] = 'type';
            $fieldsToFetch[] = 'category';
            if ($field === 'type') {
                $fieldsToFetch[] = 'value';
            }
        } else {
            $fieldsToFetch[] = $field;
        }
        $params = array(
            'conditions' => array('Attribute.id' => $id),
            'fields' => $fieldsToFetch,
            'flatten' => 1,
            'contain' => array(
                'Event' => array(
                    'fields' => array('distribution', 'id', 'user_id', 'orgc_id'),
                )
            )
        );
        $attribute = $this->Attribute->fetchAttributes($this->Auth->user(), $params);
        if (empty($attribute)) {
            throw new NotFoundException(__('Invalid attribute'));
        }
        $attribute = $attribute[0];
        if (!$this->__canModifyEvent($attribute)) {
            throw new ForbiddenException(__('You do not have permission to do that'));
        }
        $this->layout = false;
        if ($field === 'distribution') {
            $distributionLevels = $this->Attribute->shortDist;
            unset($distributionLevels[4]);
            $this->set('distributionLevels', $distributionLevels);
        } elseif ($field === 'category') {
            $possibleCategories = [];
            foreach ($this->Attribute->categoryDefinitions as $k => $category) {
                if (in_array($attribute['Attribute']['type'], $category['types'], true)) {
                    $possibleCategories[] = $k;
                }
            }
            $this->set('possibleCategories', $possibleCategories);
        } elseif ($field === 'type') {
            $possibleTypes = $this->Attribute->categoryDefinitions[$attribute['Attribute']['category']]['types'];
            $validTypes = AttributeValidationTool::validTypesForValue($possibleTypes, $this->Attribute->getCompositeTypes(), $attribute['Attribute']['value']);
            $options = [];
            foreach ($possibleTypes as $possibleType) {
                if ($this->Attribute->typeIsAttachment($possibleType)) {
                    continue; // skip attachment types
                }
                $options[] = [
                    'name' => $possibleType,
                    'value' => $possibleType,
                    'disabled' => !in_array($possibleType, $validTypes, true),
                ];
            }
            $this->set('options', $options);
        }
        $this->set('object', $attribute['Attribute']);
        $fieldURL = ucfirst($field);
        $this->render('ajax/attributeEdit' . $fieldURL . 'Form');
    }


    public function attributeReplace($id)
    {
        $event = $this->Attribute->Event->find('first', array(
            'conditions' => array('Event.id' => $id),
            'fields' => array('id', 'orgc_id', 'distribution', 'user_id'),
            'recursive' => -1
        ));
        if (empty($event) || !$this->__canModifyEvent($event)) {
            throw new MethodNotAllowedException(__('Event not found or you don\'t have permissions to create attributes'));
        }
        $this->set('event_id', $id);
        if ($this->request->is('get')) {
            $this->layout = false;
            $this->request->data['Attribute']['event_id'] = $id;

            // combobox for types
            $types = array_keys($this->Attribute->typeDefinitions);
            $types = $this->_arrayToValuesIndexArray($types);
            $this->set('types', $types);
            // combobox for categories
            $categories = array_keys($this->Attribute->categoryDefinitions);
            $categories = $this->_arrayToValuesIndexArray($categories);
            $this->set('categories', $categories);
            $this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
            $this->set('typeDefinitions', $this->Attribute->typeDefinitions);
            $this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);

        } elseif ($this->request->is('post')) {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException(__('This action can only be accessed via AJAX.'));
            }

            $newValues = explode(PHP_EOL, $this->request->data['Attribute']['value']);
            $category = $this->request->data['Attribute']['category'];
            $type = $this->request->data['Attribute']['type'];
            $to_ids = $this->request->data['Attribute']['to_ids'];

            $oldAttributes = $this->Attribute->find('all', array(
                'conditions' => array(
                    'event_id' => $id,
                    'category' => $category,
                    'type' => $type,
                ),
                'fields' => array('id', 'event_id', 'category', 'type', 'value'),
                'recursive' => -1,
            ));
            $results = array('untouched' => count($oldAttributes), 'created' => 0, 'deleted' => 0, 'createdFail' => 0, 'deletedFail' => 0);

            $newValues = array_map('trim', $newValues);

            foreach ($newValues as $value) {
                $found = false;
                foreach ($oldAttributes as $old) {
                    if ($value == $old['Attribute']['value']) {
                        $found = true;
                    }
                }
                if (!$found) {
                    $attribute = array(
                        'value' => $value,
                        'event_id' => $id,
                        'category' => $category,
                        'type' => $type,
                        'distribution' => $event['Event']['distribution'],
                        'to_ids' => $to_ids,
                    );
                    $this->Attribute->create();
                    if ($this->Attribute->save(array('Attribute' => $attribute))) {
                        $results['created']++;
                    } else {
                        $results['createdFail']++;
                    }
                }
            }

            foreach ($oldAttributes as $old) {
                if (!in_array($old['Attribute']['value'], $newValues)) {
                    if ($this->Attribute->delete($old['Attribute']['id'])) {
                        $results['deleted']++;
                        $results['untouched']--;
                    } else {
                        $results['deletedFail']++;
                    }
                }
            }
            $message = '';
            $success = true;
            if (($results['created'] > 0 || $results['deleted'] > 0) && $results['createdFail'] == 0 && $results['deletedFail'] == 0) {
                $message .= 'Update completed without any issues.';
                $this->Attribute->Event->unpublishEvent($id);
            } else {
                $message .= 'Update completed with some errors.';
                $success = false;
            }

            if ($results['created']) {
                $message .= $results['created'] . ' attribute' . $this->__checkCountForOne($results['created']) . ' created. ';
            }
            if ($results['createdFail']) {
                $message .= $results['createdFail'] . ' attribute' . $this->__checkCountForOne($results['createdFail']) . ' could not be created. ';
            }
            if ($results['deleted']) {
                $message .= $results['deleted'] . ' attribute' . $this->__checkCountForOne($results['deleted']) . ' deleted.';
            }
            if ($results['deletedFail']) {
                $message .= $results['deletedFail'] . ' attribute' . $this->__checkCountForOne($results['deletedFail']) . ' could not be deleted. ';
            }
            $message .= $results['untouched'] . ' attributes left untouched. ';

            $this->autoRender = false;
            $this->layout = false;
            if ($success) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message)), 'status'=>200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => $message)), 'status'=>200, 'type' => 'json'));
            }
        }
    }

    private function __checkCountForOne($number)
    {
        if ($number != 1) {
            return 's';
        }
        return '';
    }

    // download a sample by passing along an md5
    public function downloadSample($hash=false, $allSamples=false, $eventID=false)
    {
        if (!$this->userRole['perm_auth']) {
            throw new MethodNotAllowedException(__('This functionality requires API key access.'));
        }
        $error = false;
        if ($this->response->type() === 'application/json') {
            $data = $this->request->input('json_decode', true);
        } elseif ($this->response->type() === 'application/xml') {
            $data = $this->request->data;
        } else {
            throw new BadRequestException(__('This action is for the API only. Please refer to the automation page for information on how to use it.'));
        }
        if (!$hash && isset($data['request']['hash'])) {
            $hash = $data['request']['hash'];
        }
        if (!$allSamples && isset($data['request']['allSamples'])) {
            $allSamples = $data['request']['allSamples'];
        }
        if (!$eventID && isset($data['request']['eventID'])) {
            $eventID = $data['request']['eventID'];
        }
        if (!$eventID && !$hash) {
            throw new MethodNotAllowedException(__('No hash or event ID received. You need to set at least one of the two.'));
        }
        if (!$hash) {
            $allSamples = true;
        }


        $simpleFalse = array('hash', 'allSamples', 'eventID');
        foreach ($simpleFalse as $sF) {
            if (!is_array(${$sF}) && (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false')) {
                ${$sF} = false;
            }
        }

        // valid combinations of settings are:
        // hash
        // eventID + all samples
        // hash + eventID
        // hash + eventID + all samples

        $searchConditions = array();
        $types = array();
        if ($hash) {
            $validTypes = $this->Attribute->resolveHashType($hash);
            if ($allSamples) {
                if (empty($validTypes)) {
                    $error = 'Invalid hash format (valid options are ' . implode(', ', array_keys(Attribute::FILE_HASH_TYPES)) . ')';
                } else {
                    foreach ($validTypes as $t) {
                        if ($t === 'md5') {
                            $types = array_merge($types, array('malware-sample', 'filename|md5', 'md5'));
                        } else {
                            $types = array_merge($types, array('filename|' . $t, $t));
                        }
                    }
                }
                if (empty($error)) {
                    $event_ids = $this->Attribute->find('column', array(
                        'recursive' => -1,
                        'contain' => array('Event'),
                        'fields' => array('Event.id'),
                        'conditions' => array(
                            'OR' => array(
                                'AND' => array(
                                    'LOWER(Attribute.value1) LIKE' => strtolower($hash),
                                    'Attribute.value2' => '',
                                ),
                                'LOWER(Attribute.value2) LIKE' => strtolower($hash)
                            )
                        ),
                    ));
                    $searchConditions = array(
                        'AND' => array('Event.id' => $event_ids)
                    );
                    if (empty($event_ids)) {
                        $error = 'No hits with the given parameters.';
                    }
                }
            } else {
                if (!in_array('md5', $validTypes)) {
                    $error = 'Only MD5 hashes can be used to fetch malware samples at this point in time.';
                }
                if (empty($error)) {
                    $searchConditions = array('AND' => array('LOWER(Attribute.value2) LIKE' => strtolower($hash)));
                }
            }
        }

        if (!empty($eventID)) {
            $searchConditions['AND'][] = array('Event.id' => $eventID);
        }

        if (empty($error)) {
            $attributes = $this->Attribute->fetchAttributes(
                $this->Auth->user(),
                array(
                    'fields' => array('Attribute.event_id', 'Attribute.id', 'Attribute.value1', 'Attribute.value2', 'Event.info'),
                    'conditions' => array(
                        'AND' => array(
                            $searchConditions,
                            array('Attribute.type' => 'malware-sample')
                        )
                    ),
                    'contain' => array('Event'),
                    'flatten' => 1
                )
            );
            if (empty($attributes)) {
                $error = 'No hits with the given parameters.';
            }

            $results = array();
            foreach ($attributes as $attribute) {
                $found = false;
                foreach ($results as $previous) {
                    if ($previous['md5'] == $attribute['Attribute']['value2']) {
                        $found = true;
                    }
                }
                if (!$found) {
                    $results[] = array(
                        'md5' => $attribute['Attribute']['value2'],
                        'base64' => $this->Attribute->base64EncodeAttachment($attribute['Attribute']),
                        'filename' => $attribute['Attribute']['value1'],
                        'attribute_id' => $attribute['Attribute']['id'],
                        'event_id' => $attribute['Attribute']['event_id'],
                        'event_info' => $attribute['Event']['info'],
                    );
                }
            }
            if ($error) {
                $this->set('message', $error);
                $this->set('_serialize', array('message'));
            } else {
                $this->set('result', $results);
                $this->set('_serialize', array('result'));
            }
        } else {
            $this->set('message', $error);
            $this->set('_serialize', array('message'));
        }
    }

    public function pruneOrphanedAttributes()
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('post')) {
            throw new MethodNotAllowedException(__('You are not authorised to do that.'));
        }
        $events = array_keys($this->Attribute->Event->find('list'));
        $orphans = $this->Attribute->find('list', array('conditions' => array('Attribute.event_id !=' => $events)));
        if (count($orphans) > 0) {
            $this->Attribute->deleteAll(array('Attribute.event_id !=' => $events), false, true);
        }
        $this->Flash->success('Removed ' . count($orphans) . ' attribute(s).');
        $this->redirect(Router::url($this->referer(), true));
    }

    public function checkOrphanedAttributes()
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException(__('You are not authorised to do that.'));
        }
        $this->loadModel('Attribute');
        $events = array_keys($this->Attribute->Event->find('list'));
        $orphans = $this->Attribute->find('list', array('conditions' => array('Attribute.event_id !=' => $events)));
        return new CakeResponse(array('body'=> count($orphans), 'status'=>200, 'type' => 'json'));
    }

    public function updateAttributeValues($script)
    {
        if (!$this->_isSiteAdmin() || !$this->request->is('post')) {
            throw new MethodNotAllowedException(__('You are not authorised to do that.'));
        }
        switch ($script) {
            case 'urlSanitisation':
                $replaceConditions = array(
                    array('search' => 'UPPER(Attribute.value1) LIKE', 'from' => 'HXXP', 'to' => 'http', 'ci' => true, 'condition' => 'startsWith'),
                    array('search' => 'Attribute.value1 LIKE', 'from' => '[.]', 'to' => '.', 'ci' => false, 'condition' => 'contains'),
                );
                break;
            default:
                throw new Exception(__('Invalid script.'));
        }
        $counter = 0;
        foreach ($replaceConditions as $rC) {
            $searchPattern = '';
            if (in_array($rC['condition'], array('endsWith', 'contains'))) {
                $searchPattern .= '%';
            }
            $searchPattern .= $rC['from'];
            if (in_array($rC['condition'], array('startsWith', 'contains'))) {
                $searchPattern .= '%';
            }
            $attributes = $this->Attribute->find('all', array('conditions' => array($rC['search'] => $searchPattern), 'recursive' => -1));
            foreach ($attributes as $attribute) {
                $regex = '/';
                if (!in_array($rC['condition'], array('startsWith', 'contains'))) {
                    $regex .= '^';
                }
                $regex .= $rC['from'];
                if (!in_array($rC['condition'], array('endsWith', 'contains'))) {
                    $regex .= '$';
                }
                $regex .= '/';
                if ($rC['ci']) {
                    $regex .= 'i';
                }
                $attribute['Attribute']['value'] = preg_replace($regex, $rC['to'], $attribute['Attribute']['value']);
                $this->Attribute->save($attribute);
                $counter++;
            }
        }
        $this->Flash->success('Updated ' . $counter . ' attribute(s).');
        $this->redirect('/pages/display/administration');
    }

    public function hoverEnrichment($id, $persistent = false)
    {
        $attribute = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id), 'flatten' => 1, 'includeEventTags' => 1));
        if (empty($attribute)) {
            throw new NotFoundException(__('Invalid Attribute'));
        }
        $this->loadModel('Module');
        $modules = $this->Module->getEnabledModules($this->Auth->user());
        $validTypes = array();
        if (isset($modules['hover_type'][$attribute[0]['Attribute']['type']])) {
            $validTypes = $modules['hover_type'][$attribute[0]['Attribute']['type']];
        }
        $resultArray = array();
        foreach ($validTypes as $type) {
            $options = array();
            $found = false;
            foreach ($modules['modules'] as $temp) {
                if ($temp['name'] === $type) {
                    $found = true;
                    $format = isset($temp['mispattributes']['format']) ? $temp['mispattributes']['format'] : 'simplified';
                    if (isset($temp['meta']['config'])) {
                        foreach ($temp['meta']['config'] as $conf) {
                            $options[$conf] = Configure::read('Plugin.Enrichment_' . $type . '_' . $conf);
                        }
                    }
                    break;
                }
            }
            if (!$found) {
                throw new MethodNotAllowedException(__('No valid enrichment options found for this attribute.'));
            }
            $data = array('module' => $type);
            if ($persistent) {
                $data['persistent'] = 1;
            }
            if (!empty($options)) {
                $data['config'] = $options;
            }
            if ($format == 'misp_standard') {
                $data['attribute'] = in_array('value', $attribute) ? $attribute : $attribute[0]['Attribute'];
            } else {
                $data[$attribute[0]['Attribute']['type']] = $attribute[0]['Attribute']['value'];
            }
            $result = $this->Module->queryModuleServer($data, true, 'Enrichment', false, $attribute[0]);
            if ($result) {
                if (!is_array($result)) {
                    $resultArray[$type] = ['error' => $result];
                    continue;
                }
            } else {
                // TODO: i18n?
                $resultArray[$type] = ['error' => 'Enrichment service not reachable.'];
                continue;
            }
            $current_result = array();
            if (isset($result['results']['Object'])) {
                if (!empty($result['results']['Object'])) {
                    $objects = array();
                    foreach ($result['results']['Object'] as $object) {
                        if (isset($object['Attribute']) && !empty($object['Attribute'])) {
                            $object_attributes = array();
                            foreach($object['Attribute'] as $object_attribute) {
                                $object_attributes[] = [
                                    'object_relation' => $object_attribute['object_relation'],
                                    'value' => $object_attribute['value'],
                                    'type' => $object_attribute['type'],
                                ];
                            }
                            $objects[] = array('name' => $object['name'], 'Attribute' => $object_attributes);
                        }
                    }
                    $current_result['Object'] = $objects;
                }
                unset($result['results']['Object']);
            }
            if (isset($result['results']['Attribute'])) {
                if (!empty($result['results']['Attribute'])) {
                    $attributes = array();
                    foreach($result['results']['Attribute'] as $result_attribute) {
                        $attributes[] = array('type' => $result_attribute['type'], 'value' => $result_attribute['value']);
                    }
                    $current_result['Attribute'] = $attributes;
                }
                unset($result['results']['Attribute']);
            }
            $resultArray[$type] = $current_result;
            if (!empty($result['results'])) {
                foreach ($result['results'] as $r) {
                    if (is_array($r['values']) && !empty($r['values'])) {
                        $tempArray = array();
                        foreach ($r['values'] as $k => $v) {
                            if (is_array($v)) {
                                $v = 'Array returned';
                            }
                            $tempArray[$k] = $v;
                        }
                        $resultArray[$type][] = array($type => $tempArray);
                    } elseif ($r['values'] == null) {
                        $resultArray[$type][] = array($type => 'No result');
                    } else {
                        $resultArray[$type][] = array($type => $r['values']);
                    }
                }
            }
        }
        $this->set('persistent', $persistent);
        $this->set('results', $resultArray);
        $this->layout = false;
        $this->render('ajax/hover_enrichment');
    }

    public function describeTypes()
    {
        $result = array();
        foreach ($this->Attribute->typeDefinitions as $key => $value) {
            $result['sane_defaults'][$key] = array('default_category' => $value['default_category'], 'to_ids' => $value['to_ids']);
        }
        $result['types'] = array_keys($this->Attribute->typeDefinitions);
        $result['categories'] = array_keys($this->Attribute->categoryDefinitions);
        foreach ($this->Attribute->categoryDefinitions as $cat => $data) {
            $result['category_type_mappings'][$cat] = $data['types'];
        }
        return $this->RestResponse->viewData(['result' => $result], 'json');
    }

    public function attributeStatistics($type = 'type', $percentage = false)
    {
        $validTypes = array('type', 'category');
        if (!in_array($type, $validTypes)) {
            throw new MethodNotAllowedException(__('Invalid type requested.'));
        }
        $totalAttributes = $this->Attribute->find('count', array());
        $attributes = $this->Attribute->find('all', array(
            'recursive' => -1,
            'fields' => array($type, 'COUNT(id) as attribute_count'),
            'group' => array($type),
            'order' => ''
        ));
        $results = array();
        foreach ($attributes as $attribute) {
            if ($percentage) {
                $results[$attribute['Attribute'][$type]] = round(100 * $attribute[0]['attribute_count'] / $totalAttributes, 3) . '%';
            } else {
                $results[$attribute['Attribute'][$type]] = $attribute[0]['attribute_count'];
            }
        }
        ksort($results);
        return $this->RestResponse->viewData($results, 'json');
    }

    public function addTag($id = false, $tag_id = false)
    {
        $rearrangeRules = array(
            'request' => false,
            'Attribute' => false,
            'tag_id' => 'tag',
            'attribute_id' => 'attribute',
            'id' => 'attribute'
        );
        $RearrangeTool = new RequestRearrangeTool();
        $this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
        $local = empty($this->request->params['named']['local']) ? 0 : 1;
        if (!$this->request->is('post')) {
            if ($id === false) {
                throw new NotFoundException(__('Invalid attribute'));
            }
            $this->set('local', $local);
            $this->set('object_id', $id);
            $this->set('scope', 'Attribute');
            $this->layout = false;
            $this->autoRender = false;
            $this->render('/Events/add_tag');
        } else {
            if ($id === false) {
                if (!isset($this->request->data['attribute'])) {
                    throw new NotFoundException(__('Invalid attribute'));
                }
                $id = $this->request->data['attribute'];
            }
            if ($id === 'selected') {
                if (!isset($this->request->data['attribute_ids'])) {
                    throw new NotFoundException(__('Invalid attribute'));
                }
                $idList = json_decode($this->request->data['attribute_ids'], true);
            }
            if ($tag_id === false) {
                if (!isset($this->request->data['tag'])) {
                    throw new NotFoundException(__('Invalid tag'));
                }
                $tag_id = $this->request->data['tag'];
            }
            if (!is_numeric($tag_id)) {
                if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                    $tagChoice = explode('_', $tag_id)[1];
                    $this->loadModel('TagCollection');
                    $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), array('conditions' => array('TagCollection.id' => $tagChoice)));
                    if (empty($tagCollection)) {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag Collection.')), 'status'=>200, 'type' => 'json'));
                    }
                    $tag_id_list = array_column($tagCollection[0]['TagCollectionTag'], 'tag_id');
                } else {
                    // try to parse json array
                    $tag_ids = json_decode($tag_id);
                    if ($tag_ids !== null) { // can decode json
                        $tag_id_list = array();
                        foreach ($tag_ids as $tag_id) {
                            if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                                $tagChoice = explode('_', $tag_id)[1];
                                $this->loadModel('TagCollection');
                                $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), array('conditions' => array('TagCollection.id' => $tagChoice)));
                                if (empty($tagCollection)) {
                                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag Collection.')), 'status'=>200, 'type' => 'json'));
                                }
                                $tag_id_list = array_column($tagCollection[0]['TagCollectionTag'], 'tag_id');
                            } else {
                                $tag_id_list[] = $tag_id;
                            }
                        }
                    } else {
                        $tagId = $this->Attribute->AttributeTag->Tag->lookupTagIdForUser($this->Auth->user(), trim($tag_id));
                        if (empty($tagId)) {
                            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status'=>200, 'type' => 'json'));
                        }
                        $tag_id = $tagId;
                    }
                }
            }
            if (!isset($idList)) {
                $idList = array($id);
            }
            if (empty($tag_id_list)) {
                $tag_id_list = array($tag_id);
            }

            $conditions = $this->Attribute->AttributeTag->Tag->createConditions($this->Auth->user());
            $conditions['Tag.id'] = $tag_id_list;
            $tags = $this->Attribute->AttributeTag->Tag->find('list', array(
                'conditions' => $conditions,
                'fields' => ['Tag.id', 'Tag.name'],
            ));

            $success = 0;
            $fails = 0;
            $this->Taxonomy = ClassRegistry::init('Taxonomy');
            foreach ($idList as $id) {
                $conditions = $this->__idToConditions($id);
                $conditions['Attribute.deleted'] = 0;
                $attribute = $this->Attribute->fetchAttributeSimple($this->Auth->user(), [
                    'conditions' => $conditions,
                ]);
                if (empty($attribute)) {
                    throw new NotFoundException(__('Invalid attribute'));
                }
                $id = $attribute['Attribute']['id'];
                if (!$this->__canModifyTag($attribute, $local)) {
                    $fails++;
                    continue;
                }
                if (!$this->_isRest()) {
                    $this->Attribute->Event->insertLock($this->Auth->user(), $attribute['Event']['id']);
                }
                $changeTimestamp = false;
                foreach ($tag_id_list as $tag_id) {
                    if (!isset($tags[$tag_id])) {
                        // Tag not found or user don't have permission to add it.
                        $fails++;
                        continue;
                    }
                    $tagName = $tags[$tag_id];
                    $found = $this->Attribute->AttributeTag->hasAny([
                        'attribute_id' => $id,
                        'tag_id' => $tag_id,
                    ]);
                    if ($found) {
                        // Tag is already assigned to given attribute.
                        $fails++;
                        continue;
                    }
                    $tagsOnAttribute = $this->Attribute->AttributeTag->find('column', array(
                        'conditions' => array(
                            'AttributeTag.attribute_id' => $id,
                            'AttributeTag.local' => $local,
                        ),
                        'contain' => 'Tag',
                        'fields' => array('Tag.name'),
                    ));
                    $exclusiveTestPassed = $this->Taxonomy->checkIfNewTagIsAllowedByTaxonomy($tagName, $tagsOnAttribute);
                    if (!$exclusiveTestPassed) {
                        $fails++;
                        continue;
                    }
                    $this->Attribute->AttributeTag->create();
                    if ($this->Attribute->AttributeTag->save(array('attribute_id' => $id, 'tag_id' => $tag_id, 'event_id' => $attribute['Event']['id'], 'local' => $local))) {
                        if (!$local) {
                            $changeTimestamp = true;
                        }
                        $log = ClassRegistry::init('Log');
                        $log->createLogEntry(
                            $this->Auth->user(),
                            'tag',
                            'Attribute',
                            $id,
                            sprintf(
                                'Attached%s tag (%s) "%s" to attribute (%s)',
                                $local ? ' local' : '',
                                $tag_id,
                                $tagName,
                                $id
                            ),
                            sprintf(
                                'Attribute (%s) tagged as Tag (%s)%s',
                                $id,
                                $tag_id,
                                $local ? ' locally' : ''
                            )
                        );
                        $success++;
                    } else {
                        $fails++;
                    }
                }
                if ($changeTimestamp) {
                    $this->Attribute->touch($attribute);
                }
            }
            if ($fails === 0) {
                $message = __n('Tag added.', '%s tags added', $success, $success);
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message, 'check_publish' => true)), 'status' => 200, 'type' => 'json'));
            } else {
                $message = __n('Tag could not be added.', '%s tags could not be added.', $fails, $fails);
                if ($success > 0) {
                    $message .= __n(' However, %s tag was added.', ' However, %s tags were added.', $success, $success);
                }
                return new CakeResponse(array('body' => json_encode(array('saved' => false, 'errors' => $message)), 'status' => 200, 'type' => 'json'));
            }
        }
    }

    public function removeTag($id = false, $tag_id = false)
    {
        if (!$this->request->is('post')) {
            $attribute = $this->Attribute->fetchAttributeSimple($this->Auth->user(), [
                'conditions' => $this->__idToConditions($id)
            ]);
            if (!$attribute) {
                throw new NotFoundException(__('Invalid attribute'));
            }
            $attributeTag = $this->Attribute->AttributeTag->find('first', array(
                'conditions' => array(
                    'attribute_id' => $attribute['Attribute']['id'],
                    'tag_id' => $tag_id,
                ),
                'contain' => ['Tag'],
                'recursive' => -1,
            ));
            if (!$attributeTag) {
                throw new NotFoundException(__('Invalid tag.'));
            }

            $this->set('is_local', $attributeTag['AttributeTag']['local']);
            $this->set('tag', $attributeTag);
            $this->set('id', $attribute['Attribute']['id']);
            $this->set('tag_id', $tag_id);
            $this->set('model', 'Attribute');
            $this->set('model_name', $attribute['Attribute']['id']);
            $this->render('ajax/tagRemoveConfirmation');
        } else {
            $rearrangeRules = array(
                'request' => false,
                'Attribute' => false,
                'tag_id' => 'tag',
                'attribute_id' => 'attribute',
                'id' => 'attribute'
            );
            $RearrangeTool = new RequestRearrangeTool();
            $this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
            if ($id === false) {
                if (!isset($this->request->data['attribute'])) {
                    throw new NotFoundException(__('Invalid attribute'));
                }
                $id = $this->request->data['attribute'];
            }
            if ($tag_id === false) {
                if (!isset($this->request->data['tag'])) {
                    throw new NotFoundException(__('Invalid tag'));
                }
                $tag_id = $this->request->data['tag'];
            }
            $attribute = $this->Attribute->find('first', [
                'recursive' => -1,
                'conditions' => ['Attribute.id' => $id],
                'fields' => ['Attribute.deleted', 'Attribute.event_id', 'Attribute.id', 'Attribute.object_id', 'Event.orgc_id', 'Event.user_id'],
                'contain' => ['Event'],
            ]);
            if (empty($attribute) || $attribute['Attribute']['deleted']) {
                throw new NotFoundException(__('Invalid attribute'));
            }
            if (empty($tag_id)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status' => 200, 'type' => 'json'));
            }
            if (!is_numeric($tag_id)) {
                $tag = $this->Attribute->AttributeTag->Tag->find('first', array('recursive' => -1, 'conditions' => array('LOWER(Tag.name) LIKE' => strtolower(trim($tag_id)))));
                if (empty($tag)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status' => 200, 'type' => 'json'));
                }
                $tag_id = $tag['Tag']['id'];
            }
            if (!is_numeric($id)) {
                $id = $this->request->data['Attribute']['id'];
            }
            if (!$this->_isRest()) {
                $this->Attribute->Event->insertLock($this->Auth->user(), $attribute['Attribute']['event_id']);
            }
            $attributeTag = $this->Attribute->AttributeTag->find('first', array(
                'conditions' => array(
                    'attribute_id' => $id,
                    'tag_id' => $tag_id
                ),
                'recursive' => -1,
            ));
            // org should allow to (un)tag too, so that an event that gets pushed can be (un)tagged locally by the owning org
            if (!$this->__canModifyTag($attribute, !empty($attributeTag['AttributeTag']['local']))) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You do not have permission to do that.')), 'status' => 200, 'type' => 'json'));
            }
            if (empty($attributeTag)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid attribute - tag combination.')), 'status' => 200, 'type' => 'json'));
            }
            if ($this->Attribute->AttributeTag->delete($attributeTag['AttributeTag']['id'])) {
                if (empty($attributeTag['AttributeTag']['local'])) {
                    $this->Attribute->touch($attribute);
                }

                $tag = $this->Attribute->AttributeTag->Tag->find('first', array(
                    'conditions' => array('Tag.id' => $tag_id),
                    'recursive' => -1,
                    'fields' => array('Tag.name')
                ));
                $log = ClassRegistry::init('Log');
                $log->createLogEntry($this->Auth->user(), 'tag', 'Attribute', $id, 'Removed tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" from attribute (' . $id . ')', 'Attribute (' . $id . ') untagged of Tag (' . $tag_id . ')');
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Tag removed.', 'check_publish' => empty($attributeTag['AttributeTag']['local']))), 'status' => 200, 'type'=> 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Tag could not be removed.')), 'status' => 200, 'type' => 'json'));
            }
        }
    }

    public function toggleCorrelation($id)
    {
        if (!$this->_isSiteAdmin() && !Configure::read('MISP.allow_disabling_correlation')) {
            throw new MethodNotAllowedException(__('Disabling the correlation is not permitted on this instance.'));
        }
        $attribute = $this->Attribute->find('first', array(
            'conditions' => array('Attribute.id' => $id),
            'recursive' => -1,
            'contain' => array('Event')
        ));
        if (empty($attribute)) {
            throw new NotFoundException(__('Invalid Attribute.'));
        }
        if (!$this->__canModifyEvent($attribute)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        if (!$this->_isRest()) {
            $this->Attribute->Event->insertLock($this->Auth->user(), $attribute['Event']['id']);
        }
        if ($this->request->is('post')) {
            if ($attribute['Attribute']['disable_correlation']) {
                $attribute['Attribute']['disable_correlation'] = 0;
            } else {
                $attribute['Attribute']['disable_correlation'] = 1;
            }
            $this->Attribute->save($attribute, ['parentEvent' => $attribute]);
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('attributes', 'toggleCorrelation', $id, false, 'Correlation ' . ($attribute['Attribute']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => ('Correlation ' . ($attribute['Attribute']['disable_correlation'] ? 'disabled' : 'enabled')), 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
            }
        } else {
            $this->set('attribute', $attribute);
            $this->render('ajax/toggle_correlation');
        }
    }

    public function toggleToIDS($id)
    {
        return $this->fetchEditForm($id, 'to_ids');
    }

    public function checkAttachments()
    {
        $attributes = $this->Attribute->find(
                'all',
                array(
                    'conditions' => array('Attribute.type' => array('attachment', 'malware-sample')),
                    'contain' => ['Event.orgc_id', 'Event.org_id'],
                    'recursive' => -1
                )
            );
        $counter = 0;
        $attachmentTool = new AttachmentTool();
        $results = [];
        foreach ($attributes as $attribute) {
            $exists = $attachmentTool->exists($attribute['Attribute']['event_id'], $attribute['Attribute']['id']);
            if (!$exists) {
                $results['affectedEvents'][$attribute['Attribute']['event_id']] = $attribute['Attribute']['event_id'];
                $results['affectedAttributes'][] = $attribute['Attribute']['id'];
                foreach (['orgc', 'org'] as $type) {
                    if (empty($results['affectedOrgs'][$type][$attribute['Event'][$type . '_id']])) {
                        $results['affectedOrgs'][$type][$attribute['Event'][$type . '_id']] = 0;
                    } else {
                        $results['affectedOrgs'][$type][$attribute['Event'][$type . '_id']] += 1;
                    }
                }
                $counter++;
            }
        }
        if (!empty($results)) {
            $results['affectedEvents'] = array_values($results['affectedEvents']);
            rsort($results['affectedEvents']);
            rsort($results['affectedAttributes']);
            foreach (['orgc', 'org'] as $type) {
                arsort($results['affectedOrgs'][$type]);
            }
        }
        file_put_contents(APP . '/tmp/logs/missing_attachments.log', json_encode($results, JSON_PRETTY_PRINT));
        return new CakeResponse(array('body' => $counter, 'status' => 200));
    }

    public function exportSearch($type = false)
    {
        $filters = $this->Session->read('search_attributes_filters');
        if ($filters === null) {
            throw new NotFoundException('No search to export.');
        }

        if (empty($type)) {
            $exports = array_keys($this->Attribute->validFormats);
            $this->set('exports', $exports);
            $this->render('ajax/exportSearch');
        } else {
            $filters = $this->_jsonDecode($filters);
            $final = $this->Attribute->restSearch($this->Auth->user(), $type, $filters);
            $responseType = $this->Attribute->validFormats[$type][0];
            return $this->RestResponse->viewData($final, $responseType, false, true, 'search.' . $type . '.' . $responseType);
        }
    }

    /**
     * @param int|string $id Attribute ID or UUID
     * @return array
     * @throws Exception
     */
    private function __fetchAttribute($id)
    {
        $options = array(
            'conditions' => $this->__idToConditions($id),
            'contain' => array(
                'Event',
            ),
            'withAttachments' => $this->_isRest(),
            'flatten' => true,
            'includeAllTags' => false,
            'includeAttributeUuid' => true,
            'limit' => 1,
        );
        $attributes = $this->Attribute->fetchAttributes($this->Auth->user(), $options);
        if (!empty($attributes)) {
            return $attributes[0];
        } else {
            return null;
        }
    }

    /**
     * @param int|string $id Attribute ID or UUID
     * @return array
     */
    private function __idToConditions($id)
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

    /**
     * @param int $sharingGroupId
     * @return bool
     */
    private function __canUseSharingGroup($sharingGroupId)
    {
        $sg = $this->Attribute->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', true, $sharingGroupId);
        return !empty($sg);
    }

    private function __setIndexFilterConditions()
    {
        // search by attribute value
        if (isset($this->request->params['named']['searchvalue'])) {
            $v = $this->request->params['named']['searchvalue'];
            $this->paginate['conditions']['AND'][] = [
                'OR' => [
                    ['Attribute.value1' => $v],
                    ['Attribute.value2' => $v],
                ]
            ];
        }
    }

    public function viewAnalystData($id, $seed = null)
    {
        $this->Attribute->includeAnalystDataRecursive = true;
        $attribute = $this->Attribute->fetchAttributes(
            $this->Auth->user(),
            [
                'conditions' => $this->__idToConditions($id),
                'flatten' => true
            ]
        );
        if(empty($attribute)) {
            throw new NotFoundException(__('Invalid Attribute.'));
        } else {
            $attribute[0]['Attribute'] = array_merge_recursive($attribute[0]['Attribute'], $this->Attribute->attachAnalystData($attribute[0]['Attribute']));
        }
        if ($this->_isRest()) {
            $validFields = ['Note', 'Opinion', 'Relationship'];
            $results = [];
            foreach ($validFields as $field) {
                if (!empty($attribute[0]['Attribute'][$field])) {
                    $results[$field] = $attribute[0]['Attribute'][$field];
                }
            }
            return $this->RestResponse->viewData($results, $this->response->type());
        }
        $this->layout = null;
        $this->set('shortDist', $this->Attribute->shortDist);
        $this->set('object', $attribute[0]['Attribute']);
        $this->set('seed', $seed);
    }

    public function enrich($id)
    {
        $conditions = $this->__idToConditions($id);
        $attributes = $this->Attribute->fetchAttributes($this->Auth->user(), ['conditions' => $conditions, 'flatten' => true]);
        if (empty($attributes)) {
            throw new MethodNotAllowedException(__('Invalid Attribute'));
        }
        $attribute = $attributes[0];
        if (!$this->request->is('post') || !$this->_isRest()) {
            throw new MethodNotAllowedException(__('This endpoint allows for API POST requests only.'));
        }
        $modules = [];
        foreach ($this->request->data as $module => $enabled) {
            if ($enabled) {
                $modules[] = $module;
            }
        }
        $result = $this->Attribute->enrichmentRouter([
            'user' => $this->Auth->user(),
            'id' => $attribute['Attribute']['id'],
            'modules' => $modules
        ]);
        return $this->RestResponse->successResponse(0, $result);
    }
}
