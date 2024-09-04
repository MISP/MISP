<?php

App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

class TemplatesController extends AppController
{
    public $components = array('RequestHandler', 'CRUD');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'Template.id' => 'desc'
            )
    );

    public function beforeFilter()
    { // TODO REMOVE
        parent::beforeFilter();
        $this->Security->unlockedActions = array('uploadFile', 'deleteTemporaryFile', 'saveElementSorting');
    }

    public function index()
    {
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions['OR'] = array('org' => $this->Auth->user('Organisation')['name'], 'share' => 1);
        }
        if (!$this->_isSiteAdmin()) {
            $this->paginate = Set::merge($this->paginate, array(
                    'conditions' =>
                    array("OR" => array(
                            array('org' => $this->Auth->user('Organisation')['name']),
                            array('share' => 1),
            ))));
        }
        $this->set('list', $this->paginate());
    }

    public function edit($id)
    {
        $template = $this->Template->checkAuthorisation($id, $this->Auth->user(), true);
        if (!$this->_isSiteAdmin() && !$template) {
            throw new MethodNotAllowedException('No template with the provided ID exists, or you are not authorised to edit it.');
        }
        $this->set('mayModify', true);

        if ($this->request->is('post') || $this->request->is('put')) {
            $this->request->data['Template']['id'] = $id;
            unset($this->request->data['Template']['tagsPusher']);
            $tags = $this->request->data['Template']['tags'];
            unset($this->request->data['Template']['tags']);
            $this->request->data['Template']['org'] = $this->Auth->user('Organisation')['name'];
            $this->Template->create();
            if ($this->Template->save($this->request->data)) {
                $id = $this->Template->id;
                $tagArray = json_decode($tags);
                $this->loadModel('TemplateTag');
                $oldTags = $this->TemplateTag->find('all', array(
                    'conditions' => array('template_id' => $id),
                    'recursive' => -1,
                    'contain' => 'Tag'
                ));

                $newTags = $this->TemplateTag->Tag->find('all', array(
                    'recursive' => -1,
                    'conditions' => array('id' => $tagArray)
                ));

                foreach ($oldTags as $k => $oT) {
                    if (!in_array($oT['Tag'], $newTags)) {
                        $this->TemplateTag->delete($oT['TemplateTag']['id']);
                    }
                }

                foreach ($newTags as $k => $nT) {
                    if (!in_array($nT['Tag'], $oldTags)) {
                        $this->TemplateTag->create();
                        $this->TemplateTag->save(array('TemplateTag' => array('template_id' => $id, 'tag_id' => $nT['Tag']['id'])));
                    }
                }
                $this->redirect(array('action' => 'view', $this->Template->id));
            } else {
                throw new Exception('The template could not be edited.');
            }
        }
        $this->request->data = $template;

        // get all existing tags for the tag add dropdown menu
        $this->loadModel('Tags');
        $tags = $this->Tags->find('all');
        $tagArray = array();
        foreach ($tags as $tag) {
            $tagArray[$tag['Tags']['id']] = $tag['Tags']['name'];
        }

        //get all tags currently assigned to the event
        $currentTags = $this->Template->TemplateTag->find('all', array(
            'recursive' => -1,
            'contain' => 'Tag',
            'conditions' => array('template_id' => $id),
        ));
        $this->set('currentTags', $currentTags);
        $this->set('id', $id);
        $this->set('template', $template);
        $this->set('tags', $tagArray);
        $this->set('tagInfo', $tags);
        $this->render('add');
    }

    public function view($id)
    {
        if (!$this->_isSiteAdmin() && !$this->Template->checkAuthorisation($id, $this->Auth->user(), false)) {
            throw new MethodNotAllowedException('No template with the provided ID exists, or you are not authorised to see it.');
        }
        if ($this->Template->checkAuthorisation($id, $this->Auth->user(), true)) {
            $this->set('mayModify', true);
        } else {
            $this->set('mayModify', false);
        }
        $template = $this->Template->find('first', array(
            'conditions' => array(
                'id' => $id,
            ),
            'contain' => array(
                'TemplateElement',
                'TemplateTag' => array(
                    'Tag',
                ),
            ),
        ));
        if (empty($template)) {
            throw new NotFoundException('No template with the provided ID exists, or you are not authorised to see it.');
        }
        $tagArray = array();
        foreach ($template['TemplateTag'] as $tt) {
            $tagArray[] = $tt;
        }
        $this->set('id', $id);
        $this->set('template', $template);
    }

    public function add()
    {
        if (!$this->userRole['perm_template']) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if ($this->request->is('post')) {
            unset($this->request->data['Template']['tagsPusher']);
            $tags = $this->request->data['Template']['tags'];
            unset($this->request->data['Template']['tags']);
            $this->request->data['Template']['org'] = $this->Auth->user('Organisation')['name'];
            $this->Template->create();
            if ($this->Template->save($this->request->data)) {
                $id = $this->Template->id;
                $tagArray = json_decode($tags);
                $this->loadModel('TemplateTag');
                $this->loadModel('Tag');
                foreach ($tagArray as $t) {
                    $tag = $this->Tag->find('first', array(
                        'conditions' => array('id' => $t),
                        'fields' => array('id', 'name'),
                        'recursive' => -1,
                    ));
                    $this->TemplateTag->create();
                    $this->TemplateTag->save(array('TemplateTag' => array('template_id' => $id, 'tag_id' => $tag['Tag']['id'])));
                }
                $this->redirect(array('action' => 'view', $this->Template->id));
            } else {
                throw new Exception('The template could not be created.');
            }
        }
        $this->loadModel('Tags');
        $tags = $this->Tags->find('all');
        $tagArray = array();
        foreach ($tags as $tag) {
            $tagArray[$tag['Tags']['id']] = $tag['Tags']['name'];
        }
        $this->set('tags', $tagArray);
        $this->set('tagInfo', $tags);
    }

    public function saveElementSorting()
    {
        // check if user can edit the template
        $this->autoRender = false;
        $this->request->onlyAllow('ajax');
        $orderedElements = $this->request->data;
        foreach ($orderedElements as $key => $e) {
            $orderedElements[$key] = (int)ltrim($e, 'id_');
        }
        $extractedIds = array();
        foreach ($orderedElements as $element) {
            $extractedIds[] = $element;
        }
        $template_id = $this->Template->TemplateElement->find('first', array(
            'conditions' => array('id' => $extractedIds),
            'recursive' => -1,
            'fields' => array('id', 'template_id'),
        ));

        if (!$this->_isSiteAdmin() && !$this->Template->checkAuthorisation($template_id['TemplateElement']['template_id'], $this->Auth->user(), true)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You are not authorised to do that.')), 'status' => 200, 'type' => 'json'));
        }

        $elements = $this->Template->TemplateElement->find('all', array(
                'conditions' => array('template_id' => $template_id['TemplateElement']['template_id']),
                'recursive' => -1,
        ));
        if (empty($elements)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Something went wrong, the supplied template elements don\'t exist, or you are not eligible to edit them.')),'status'=>200));
        }
        if (count($elements) != count($orderedElements)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Incomplete template element list passed as argument. Expecting ' . count($elements) . ' elements, only received positions for ' . count($orderedElements) . '.')), 'status'=>200, 'type' => 'json'));
        }
        $template_id = $elements[0]['TemplateElement']['template_id'];

        foreach ($elements as $key => $e) {
            if ($template_id !== $e['TemplateElement']['template_id']) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Cannot sort template elements belonging to separate templates. You should never see this message during legitimate use.')), 'status'=>200, 'type' => 'json'));
            }
            foreach ($orderedElements as $k => $orderedElement) {
                if ($orderedElement == $e['TemplateElement']['id']) {
                    $elements[$key]['TemplateElement']['position'] = $k+1;
                }
            }
        }
        $this->Template->TemplateElement->saveMany($elements);
        return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Elements repositioned.')), 'status'=>200, 'type' => 'json'));
    }

    public function delete($id)
    {
        $this->CRUD->delete($id, [
            'validate' => function () use ($id) {
                $template = $this->Template->checkAuthorisation($id, $this->Auth->user(), true);

                if (!$this->_isSiteAdmin() && !$template) {
                    throw new MethodNotAllowedException('No template with the provided ID exists, or you are not authorised to edit it.');
                }
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function templateChoices($id)
    {
        $this->loadModel('Event');
        $event = $this->Event->find('first', array(
                'conditions' => array('id' => $id),
                'recursive' => -1,
                'fields' => array('orgc_id', 'id'),
        ));
        if (empty($event) || (!$this->_isSiteAdmin() && $event['Event']['orgc_id'] != $this->Auth->user('org_id'))) {
            throw new NotFoundException('Event not found or you are not authorised to edit it.');
        }

        $conditions = array();
        if (!$this->_isSiteAdmin) {
            $conditions['OR'] = array('Template.org' => $this->Auth->user('Organisation')['name'], 'Template.share' => 1);
        }
        $templates = $this->Template->find('all', array(
                'recursive' => -1,
                'conditions' => $conditions
        ));
        $this->set('templates', $templates);
        $this->set('id', $id);
        $this->render('ajax/template_choices');
    }

    public function populateEventFromTemplate($template_id, $event_id)
    {
        $template = $this->Template->find('first', array(
            'conditions' => array('Template.id' => $template_id),
            'contain' => array(
                'TemplateElement' => array(
                    'TemplateElementAttribute',
                    'TemplateElementText',
                    'TemplateElementFile'
                ),
                'TemplateTag' => array(
                    'Tag'
                )
            ),
        ));
        $this->loadModel('Event');
        $event = $this->Event->find('first', array(
            'conditions' => array('id' => $event_id),
            'recursive' => -1,
            'fields' => array('id', 'orgc_id', 'distribution'),
        ));
        $this->set('event', $event);
        if (empty($event)) {
            throw new MethodNotAllowedException('Event not found or you are not authorised to edit it.');
        }
        if (empty($template)) {
            throw new MethodNotAllowedException('Template not found or you are not authorised to edit it.');
        }
        if (!$this->_isSiteAdmin()) {
            if ($event['Event']['orgc_id'] != $this->Auth->user('org_id')) {
                throw new MethodNotAllowedException('Event not found or you are not authorised to edit it.');
            }
            if ($template['Template']['org'] != $this->Auth->user('Organisation')['name'] && !$template['Template']['share']) {
                throw new MethodNotAllowedException('Template not found or you are not authorised to use it.');
            }
        }

        $this->set('template_id', $template_id);
        $this->set('event_id', $event_id);
        if ($this->request->is('post')) {
            $this->set('template', $this->request->data);
            $result = $this->Event->Attribute->checkTemplateAttributes($template, $this->request->data, $event_id);
            if (isset($this->request->data['Template']['modify']) || !empty($result['errors'])) {
                $fileArray = $this->request->data['Template']['fileArray'];
                $this->set('fileArray', $fileArray);
                $this->set('errors', $result['errors']);
                $this->set('templateData', $template);
                $this->set('validTypeGroups', $this->Event->Attribute->validTypeGroups);
            } else {
                $this->set('errors', $result['errors']);
                $this->set('attributes', $result['attributes']);
                $fileArray = $this->request->data['Template']['fileArray'];
                $this->set('fileArray', $fileArray);
                $this->set('distributionLevels', $this->Event->Attribute->distributionLevels);
                $this->render('populate_event_from_template_attributes');
            }
        } else {
            $this->set('templateData', $template);
            $this->set('validTypeGroups', $this->Event->Attribute->validTypeGroups);
        }
    }


    // called when the user is finished populating a template and is has finished reviewing the resulting attributes at the last stage of the process
    public function submitEventPopulation($template_id, $event_id)
    {
        if ($this->request->is('post')) {
            $this->loadModel('Event');
            $event = $this->Event->find('first', array(
                    'conditions' => array('id' => $event_id),
                    'recursive' => -1,
                    'fields' => array('id', 'orgc_id', 'distribution', 'published'),
                    'contain' => 'EventTag',
            ));
            if (empty($event)) {
                throw new MethodNotAllowedException('Event not found or you are not authorised to edit it.');
            }
            if (!$this->_isSiteAdmin()) {
                if ($event['Event']['orgc_id'] != $this->Auth->user('org_id')) {
                    throw new MethodNotAllowedException('Event not found or you are not authorised to edit it.');
                }
            }

            $template = $this->Template->find('first', array(
                    'conditions' => array('Template.id' => $template_id),
                    'recursive' => -1,
                    'contain' => 'TemplateTag',
                    'fields' => 'id',
            ));
            foreach ($template['TemplateTag'] as $tag) {
                $exists = false;
                foreach ($event['EventTag'] as $eventTag) {
                    if ($eventTag['tag_id'] == $tag['tag_id']) {
                        $exists = true;
                    }
                }
                if (!$exists) {
                    $this->Event->EventTag->create();
                    $this->Event->EventTag->save(array('event_id' => $event_id, 'tag_id' => $tag['tag_id']));
                }
            }

            if (isset($this->request->data['Template']['attributes'])) {
                $attributes = json_decode($this->request->data['Template']['attributes'], true);
                $this->loadModel('MispAttribute');
                $fails = 0;
                foreach ($attributes as $k => $attribute) {
                    if (isset($attribute['data']) && $this->Template->checkFilename($attribute['data'])) {
                        $file = new File(APP . 'tmp/files/' . $attribute['data']);
                        $content = $file->read();
                        $attributes[$k]['data'] = base64_encode($content);
                        if ($this->Event->Attribute->typeIsMalware($attributes[$k]['type'])) {
                            $hashes = $this->Event->Attribute->handleMaliciousBase64($event_id, explode('|', $attributes[$k]['value'])[0], $attributes[$k]['data'], array('md5'));
                            $attributes[$k]['data'] = $hashes['data'];
                        }
                        $file->delete();
                    }
                    $this->MispAttribute->create();
                    if (!$this->MispAttribute->save(array('Attribute' => $attributes[$k]))) {
                        $fails++;
                    }
                }
                $count = isset($k) ? $k + 1 : 0;
                $event = $this->Event->find('first', array(
                    'conditions' => array('Event.id' => $event_id),
                    'recursive' => -1
                ));
                $event['Event']['published'] = 0;
                $date = new DateTime();
                $event['Event']['timestamp'] = $date->getTimestamp();
                $this->Event->save($event);
                if ($fails == 0) {
                    $this->Flash->success(__('Event populated, ' . $count . ' attributes successfully created.'));
                } else {
                    $this->Flash->success(__('Event populated, but ' . $fails . ' attributes could not be saved.'));
                }
                $this->redirect(array('controller' => 'events', 'action' => 'view', $event_id));
            } else {
                throw new MethodNotAllowedException('No attributes submitted for creation.');
            }
        } else {
            throw new MethodNotAllowedException();
        }
    }

    public function uploadFile($elementId, $batch)
    {
        $this->layout = 'iframe';
        $this->set('batch', $batch);
        $this->set('element_id', $elementId);
        if ($this->request->is('get')) {
            $this->set('element_id', $elementId);
        } elseif ($this->request->is('post')) {
            $fileArray = array();
            $filenames = array();
            $added = 0;
            $failed = 0;
            // filename checks
            foreach ($this->request->data['Template']['file'] as $k => $file) {
                if ($file['size'] > 0 && $file['error'] == 0) {
                    if ($this->Template->checkFilename($file['name'])) {
                        $fn = $this->Template->generateRandomFileName();
                        move_uploaded_file($file['tmp_name'], APP . 'tmp/files/' . $fn);
                        $filenames[] = $file['name'];
                        $fileArray[] = array('filename' => $file['name'], 'tmp_name' => $fn, 'element_id' => $elementId);
                        $added++;
                    } else {
                        $failed++;
                    }
                } else {
                    $failed ++;
                }
            }
            $result = $added . ' files uploaded.';
            if ($failed) {
                $result .= ' ' . $failed . ' files either failed to upload, or were empty.';
                $this->set('upload_error', true);
            } else {
                $this->set('upload_error', false);
            }
            $this->set('result', $result);
            $this->set('filenames', $filenames);
            $this->set('fileArray', json_encode($fileArray));
        }
    }

    // deletes a temporary file created by the user while populating a template
    // users can add files to attachment fields and when they change their mind about it, they can remove a file (deleting the temporary file)
    // before it gets saved as an attribute and moved to the persistent attachment store
    public function deleteTemporaryFile($filename)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This action is restricted to accepting POST requests only.');
        }
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is only accessible through AJAX.');
        }
        $this->autoRender = false;
        if ($this->Template->checkFilename($filename)) {
            $file = new File(APP . 'tmp/files/' . $filename);
            if ($file->exists()) {
                $file->delete();
            }
        }
    }
}
