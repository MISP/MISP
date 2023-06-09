<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Utility\Hash;
use Cake\Utility\Text;
use Cake\Database\Expression\QueryExpression;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\ForbiddenException;

class SightingdbsController extends AppController
{

    public $quickFilterFields = ['name', 'owner', 'host', 'namespace'];
    public $filterFields = [
        'name', 'owner', 'host', 'namespace'
    ];
    public $containFields = [];
    public $statisticsFields = ['owner'];

    public function index()
    {
        $loggedUserOrganisationNationality = $this->ACL->getUser()['Organisation']['nationality'];
        if (!empty($loggedUserOrganisationNationality)) {
            $customContextFilters[] = [
                'label' => __('Country: {0}', $loggedUserOrganisationNationality),
                'filterCondition' => [
                    'nationality' => $loggedUserOrganisationNationality,
                ]
            ];
        }

        $this->CRUD->index([
            'filters' => $this->filterFields,
            'quickFilters' => $this->quickFilterFields,
            'afterFind' => function($entity) {
                return $this->Sightingdbs->extractOrgIds($entity);
            },
            'contain' => $this->containFields
        ]);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function filtering()
    {
        $this->CRUD->filtering();
    }

    public function add()
    {
        $this->CRUD->add();
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('countries',
            array_merge(
                [
                    '' => __('Not specified')
                ],
                //$this->_arrayToValuesIndexArray($this->Organisation->getCountries())
            )
        );
        $this->set('metaGroup', 'ContactDB');
    }

    public function view($id)
    {
        $this->CRUD->view($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('metaGroup', 'ContactDB');
    }

    public function edit($id)
    {
        $currentUser = $this->ACL->getUser();
        if (
            !($currentUser['Organisation']['id'] == $id && $currentUser['Role']['perm_org_admin']) &&
            !$currentUser['Role']['perm_admin']
        ) {
            throw new MethodNotAllowedException(__('You cannot modify that organisation.'));
        }
        $this->CRUD->edit($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('metaGroup', 'ContactDB');
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('metaGroup', 'ContactDB');
    }

    public function tag($id)
    {
        $this->CRUD->tag($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function untag($id)
    {
        $this->CRUD->untag($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function viewTags($id)
    {
        $this->CRUD->viewTags($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }
}
