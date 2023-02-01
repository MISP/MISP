<?php

namespace App\Controller;

use App\Controller\AppController;
use Cake\Utility\Hash;
use Cake\Utility\Text;
use Cake\Database\Expression\QueryExpression;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\ForbiddenException;

class OrganisationsController extends AppController
{

    public $quickFilterFields = [['name' => true], 'uuid', 'nationality', 'sector', 'type', 'url', 'local'];
    public $filterFields = [
        'name', 'uuid', 'nationality', 'sector', 'type', 'url', 'local'
    ];
    public $containFields = [];
    public $statisticsFields = ['nationality', 'sector'];

    public function index()
    {
        $customContextFilters = [
            [
                'label' => __('Local orgs'),
                'filterCondition' => ['local' => 1]
            ],
            [
                'label' => __('External orgs'),
                'filterCondition' => ['local' => 0]
            ]
        ];
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
            'quickFilterForMetaField' => ['enabled' => true, 'wildcard_search' => true],
            'contextFilters' => [
                'custom' => $customContextFilters,
            ],
            'afterFind' => function($entity) {
                $entity->setVirtual(['user_count']);
                return $entity;
            },
            'contain' => $this->containFields,
            'statisticsFields' => $this->statisticsFields,
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
