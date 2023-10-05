<?php

namespace App\Controller;

use App\Controller\AppController;

class ObjectTemplateElementsController extends AppController
{
    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'ObjectTemplateElement.id' => 'desc'
        ),
        'recursive' => -1
    );

    public function viewElements($id, $context = 'all')
    {
        $this->paginate['conditions'] = array('ObjectTemplateElements.object_template_id' => $id);
        $elements = $this->paginate();
        $this->set('list', $elements);
        $this->layout = false;
        $this->render('ajax/view_elements');
    }
}
