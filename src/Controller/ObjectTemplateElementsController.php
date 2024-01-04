<?php

namespace App\Controller;

use App\Controller\AppController;

class ObjectTemplateElementsController extends AppController
{
    public $paginate = [
        'limit' => 60,
        'order' => [
            'ObjectTemplateElement.id' => 'desc'
        ],
    ];

    public function viewElements($id, $context = 'all')
    {
        $this->paginate['conditions'] = ['ObjectTemplateElements.object_template_id' => $id];
        $elements = $this->paginate();
        $this->set('list', $elements);
        $this->layout = false;
        $this->render('ajax/view_elements');
    }
}
