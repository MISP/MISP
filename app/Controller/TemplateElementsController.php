<?php

App::uses('AppController', 'Controller');

class TemplateElementsController extends AppController
{
    public $components = array('RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'TemplateElement.position' => 'asc'
            )
    );

    public function index($id)
    {
        if (!is_numeric($id)) {
            throw new MethodNotAllowedException(__('No template with the provided ID exists, or you are not authorised to see it.'));
        }
        //check permissions
        $template = $this->TemplateElement->Template->checkAuthorisation($id, $this->Auth->user(), false);
        if (!$this->_isSiteAdmin() && !$template) {
            throw new MethodNotAllowedException(__('No template with the provided ID exists, or you are not authorised to see it.'));
        }

        $templateElements = $this->TemplateElement->find('all', array(
            'conditions' => array(
                'template_id' => $id,
            ),
            'contain' => array(
                'TemplateElementAttribute',
                'TemplateElementText',
                'TemplateElementFile'
            ),
            'order' => array('TemplateElement.position ASC')
        ));
        $this->loadModel('MispAttribute');
        $this->set('validTypeGroups', $this->MispAttribute->validTypeGroups);
        $this->set('id', $id);
        $this->layout = false;
        $this->set('elements', $templateElements);
        $mayModify = false;
        if ($this->_isSiteAdmin() || $template['Template']['org'] == $this->Auth->user('Organisation')['name']) {
            $mayModify = true;
        }
        $this->set('mayModify', $mayModify);
        $this->render('ajax/ajaxIndex');
    }

    public function templateElementAddChoices($id)
    {
        if (!$this->_isSiteAdmin() && !$this->TemplateElement->Template->checkAuthorisation($id, $this->Auth->user(), true)) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is for ajax requests only.');
        }
        $this->set('id', $id);
        $this->layout = false;
        $this->render('ajax/template_element_add_choices');
    }

    public function add($type, $id)
    {
        $ModelType = 'TemplateElement' . ucfirst($type);
        if (!$this->_isSiteAdmin() && !$this->TemplateElement->Template->checkAuthorisation($id, $this->Auth->user(), true)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You are not authorised to do that.')), 'status' => 200, 'type' => 'json'));
        }
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is for ajax requests only.');
        }
        if ($this->request->is('get')) {
            $this->set('id', $id);
            if ($type == 'attribute') {
                $this->loadModel('MispAttribute');
                // combobox for types
                $types = array_keys($this->MispAttribute->typeDefinitions);
                $types = $this->_arrayToValuesIndexArray($types);
                $this->set('types', $types);
                // combobox for categories
                $categories = array_keys($this->MispAttribute->categoryDefinitions);
                $categories = $this->_arrayToValuesIndexArray($categories);
                $this->set('categories', compact('categories'));
                $this->set('attrDescriptions', $this->MispAttribute->fieldDescriptions);
                $this->set('typeDefinitions', $this->MispAttribute->typeDefinitions);
                $categoryDefinitions = $this->MispAttribute->categoryDefinitions;
                foreach ($categoryDefinitions as $k => $catDef) {
                    foreach ($catDef['types'] as $l => $t) {
                        if ($t == 'malware-sample' || $t == 'attachment') {
                            unset($categoryDefinitions[$k]['types'][$l]);
                        }
                    }
                }
                $this->set('categoryDefinitions', $categoryDefinitions);
                $this->set('validTypeGroups', $this->MispAttribute->validTypeGroups);
                $this->set('typeGroupCategoryMapping', $this->MispAttribute->typeGroupCategoryMapping);
            } elseif ($type == 'file') {
                $this->loadModel('MispAttribute');
                $categoryArray = array();
                $categories = array();
                foreach ($this->MispAttribute->categoryDefinitions as $k => $catDef) {
                    $temp = array();
                    if (in_array('malware-sample', $catDef['types'])) {
                        $temp[] = 'malware-sample';
                    }
                    if (in_array('attachment', $catDef['types'])) {
                        $temp[] = 'attachment';
                    }
                    if (!empty($temp)) {
                        $categoryArray[$k] = $temp;
                        $categories[] = $k;
                    }
                }
                $categories = $this->_arrayToValuesIndexArray($categories);
                $this->set('categoryArray', $categoryArray);
                $this->set('categories', $categories);
            }
            $this->layout = false;
            $this->render('ajax/template_element_add_' . $type);
        } elseif ($this->request->is('post')) {
            $pos = $this->TemplateElement->lastPosition($id);
            $this->TemplateElement->create();
            $templateElement = array(
                'TemplateElement' => array(
                    'template_id' => $id,
                    'position' => ++$pos,
                    'element_definition' => $type
                ),
            );
            $errorMessage = 'The element could not be added.';
            if ($this->TemplateElement->save($templateElement)) {
                $this->request->data[$ModelType]['template_element_id'] = $this->TemplateElement->id;
                $this->TemplateElement->$ModelType->create();
                if ($this->TemplateElement->$ModelType->save($this->request->data)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Element successfully added to template.')), 'status' => 200, 'type' => 'json'));
                } else {
                    $this->TemplateElement->delete($this->TemplateElement->id);
                    $errorMessage = $this->TemplateElement->$ModelType->validationErrors;
                }
            } else {
                $errorMessage = $this->TemplateElement->validationErrors;
            }
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $errorMessage)), 'status' => 200, 'type' => 'json'));
        }
    }

    public function edit($type, $id)
    {
        $ModelType = 'TemplateElement' . ucfirst($type);
        $templateElement = $this->TemplateElement->find('first', array(
            'conditions' => array('TemplateElement.id' => $id),
            'contain' => array('Template', $ModelType)
        ));
        $this->set('template_id', $templateElement['Template']['id']);
        if (!$this->_isSiteAdmin() && !$this->TemplateElement->Template->checkAuthorisation($id, $this->Auth->user(), true)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You are not authorised to do that.')), 'status' => 200, 'type' => 'json'));
        }
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is for ajax requests only.');
        }
        if ($this->request->is('get')) {
            $this->set('id', $id);
            $this->request->data[$ModelType] = $templateElement[$ModelType][0];
            if ($type == 'attribute') {
                $this->loadModel('MispAttribute');
                // combobox for types
                $types = array_keys($this->MispAttribute->typeDefinitions);
                $types = $this->_arrayToValuesIndexArray($types);
                $this->set('types', $types);
                // combobox for categories
                $categories = array_keys($this->MispAttribute->categoryDefinitions);
                $categories = $this->_arrayToValuesIndexArray($categories);
                $this->set('categories', compact('categories'));
                $categoryDefinitions = $this->MispAttribute->categoryDefinitions;
                foreach ($categoryDefinitions as $k => $catDef) {
                    foreach ($catDef['types'] as $l => $t) {
                        if ($t == 'malware-sample' || $t == 'attachment') {
                            unset($categoryDefinitions[$k]['types'][$l]);
                        }
                    }
                }
                if ($this->request->data['TemplateElementAttribute']['complex']) {
                    $this->set('initialTypes', $this->_arrayToValuesIndexArray($this->MispAttribute->typeGroupCategoryMapping[$templateElement['TemplateElementAttribute'][0]['category']]));
                } else {
                    $this->set('initialTypes', $this->_arrayToValuesIndexArray($categoryDefinitions[$templateElement['TemplateElementAttribute'][0]['category']]['types']));
                }
                $this->set('initialValues', $templateElement['TemplateElementAttribute'][0]);
                $this->set('categoryDefinitions', $categoryDefinitions);
                $this->set('validTypeGroups', $this->MispAttribute->validTypeGroups);
                $this->set('typeGroupCategoryMapping', $this->MispAttribute->typeGroupCategoryMapping);
            } elseif ($type == 'file') {
                $this->loadModel('MispAttribute');
                $categoryArray = array();
                $categories = array();
                foreach ($this->MispAttribute->categoryDefinitions as $k => $catDef) {
                    $temp = array();
                    if (in_array('malware-sample', $catDef['types'])) {
                        $temp[] = 'malware-sample';
                    }
                    if (in_array('attachment', $catDef['types'])) {
                        $temp[] = 'attachment';
                    }
                    if (!empty($temp)) {
                        $categoryArray[$k] = $temp;
                        $categories[] = $k;
                    }
                }
                $categories = $this->_arrayToValuesIndexArray($categories);
                $this->set('categoryArray', $categoryArray);
                $this->set('categories', $categories);
            }
            $this->layout = false;
            $this->render('ajax/template_element_edit_' . $type);
        } elseif ($this->request->is('post') || $this->request->is('put')) {
            $this->request->data[$ModelType]['id'] = $templateElement[$ModelType][0]['id'];
            $this->request->data[$ModelType]['template_element_id'] = $templateElement[$ModelType][0]['template_element_id'];
            if ($this->TemplateElement->$ModelType->save($this->request->data)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Element successfully edited.')), 'status' => 200, 'type' => 'json'));
            } else {
                $this->TemplateElement->delete($this->TemplateElement->id);
                $errorMessage = $this->TemplateElement->$ModelType->validationErrors;
            }
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'The element could not be edited.')), 'status' => 200, 'type' => 'json'));
        }
    }

    public function delete($id)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This action is for ajax requests only.');
        }
        $this->TemplateElement->read(null, $id);
        if (!$this->_isSiteAdmin() && !$this->TemplateElement->Template->checkAuthorisation($this->TemplateElement->data['Template']['id'], $this->Auth->user(), true)) {
            throw new NotAllowedException('You are not authorised to do that.');
        }
        if ($this->request->is('post')) {
            if ($this->_isSiteAdmin() || $this->Auth->user('Organisation')['name'] == $this->TemplateElement->data['Template']['org']) {
                // check permissions
                if (empty($this->TemplateElement->data)) {
                    throw new NotFoundException();
                }
                $type = 'TemplateElement' . ucfirst($this->TemplateElement->data['TemplateElement']['element_definition']);
                if ($this->TemplateElement->$type->delete($this->TemplateElement->data[$type][0]['id'])) {
                    $this->TemplateElement->delete($this->TemplateElement->data['TemplateElement']['id']);
                    $this->TemplateElement->Template->trimElementPositions($this->TemplateElement->data['TemplateElement']['template_id']);
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Element deleted.')), 'status' => 200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => 'Couldn\'t delete the Element')), 'status' => 200, 'type' => 'json'));
                }
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => 'You don\'t have permission to do that.')), 'status' => 200, 'type' => 'json'));
            }
        } else {
            $this->set('id', $id);
            $this->set('template_id', $this->TemplateElement->data['Template']['id']);
            $this->render('ajax/templateElementConfirmationForm');
        }
    }
}
