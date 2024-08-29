<?php
declare(strict_types=1);

namespace App\Controller;

use App\Model\Entity\Organisation;
use Cake\Http\Exception\MethodNotAllowedException;

class OrganisationsController extends AppController
{
    public $quickFilterFields = [['name' => true], 'uuid', 'nationality', 'sector', 'type', 'url', 'local'];
    public $filterFields = [
        'name', 'uuid', 'nationality', 'sector', 'type', 'url', 'local',
    ];
    public $containFields = [];
    public $statisticsFields = ['nationality', 'sector'];

    /**
     * Display the list of organizations.
     *
     * @return \Cake\Http\Response|null
     */
    public function index()
    {
        $customContextFilters = [
            [
                'label' => __('Local orgs'),
                'filterCondition' => ['local' => 1],
            ],
            [
                'label' => __('External orgs'),
                'filterCondition' => ['local' => 0],
            ],
        ];
        $loggedUserOrganisationNationality = $this->ACL->getUser()['Organisation']['nationality'];
        if (!empty($loggedUserOrganisationNationality)) {
            $customContextFilters[] = [
                'label' => __('Country: {0}', $loggedUserOrganisationNationality),
                'filterCondition' => [
                    'nationality' => $loggedUserOrganisationNationality,
                ],
            ];
        }

        $this->CRUD->index(
            [
                'filters' => $this->filterFields,
                'quickFilters' => $this->quickFilterFields,
                'quickFilterForMetaField' => ['enabled' => true, 'wildcard_search' => true],
                'contextFilters' => [
                    'custom' => $customContextFilters,
                ],
                'contain' => $this->containFields,
                'statisticsFields' => $this->statisticsFields,
            ]
        );
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    /**
     * Filtering function.
     */
    public function filtering()
    {
        $this->CRUD->filtering();
    }

    /**
     * Add a new organization.
     *
     * @return \Cake\Http\Response|null Redirects on successful add, renders view otherwise.
     */
    public function add()
    {
        $params = [
            'beforeSave' => function (Organisation $org) {
                $org['created_by'] = $this->ACL->getUser()['id'];

                return $org;
            },
        ];
        $this->CRUD->add($params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set(
            'countries',
            array_merge(
                [
                    '' => __('Not specified'),
                ],
                //$this->_arrayToValuesIndexArray($this->Organisation->getCountries())
            ),
        );
        $this->set('metaGroup', 'ContactDB');
    }

    /**
     * View an organization.
     *
     * @param int $id The ID of the organization.
     * @return \Cake\Http\Response|null The response payload.
     */
    public function view(int $id)
    {
        $this->CRUD->view($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('metaGroup', 'ContactDB');
    }

    /**
     * Edit an organization.
     *
     * @param int $id The ID of the organization.
     * @return \Cake\Http\Response|null The response payload.
     */
    public function edit(int $id)
    {
        $currentUser = $this->ACL->getUser();
        if (
            !(
                $currentUser['Role']['perm_site_admin'] ||
                ($currentUser['Organisation']['id'] == $id && $currentUser['Role']['perm_admin'])
            )
        ) {
            throw new MethodNotAllowedException(__('You cannot modify that organisation.'));
        }
        // FIXME prevent change of the created_by field
        $this->CRUD->edit($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('metaGroup', 'ContactDB');
        $this->render('add');
    }

    /**
     * Delete an organization.
     *
     * @param int $id The ID of the organization.
     * @return \Cake\Http\Response|null The response payload.
     */
    public function delete(int $id)
    {
        $this->CRUD->delete($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('metaGroup', 'ContactDB');
    }

    // /**
    //  * Tag an organization.
    //  *
    //  * @param int $id The ID of the organization.
    //  * @return \Cake\Http\Response|null The response payload.
    //  */
    // public function tag(int $id)
    // {
    //     $this->CRUD->tag($id);
    //     $responsePayload = $this->CRUD->getResponsePayload();
    //     if (!empty($responsePayload)) {
    //         return $responsePayload;
    //     }
    // }

    // /**
    //  * Untag an organization.
    //  *
    //  * @param int $id The ID of the organization.
    //  * @return \Cake\Http\Response|null The response payload.
    //  */
    // public function untag(int $id)
    // {
    //     $this->CRUD->untag($id);
    //     $responsePayload = $this->CRUD->getResponsePayload();
    //     if (!empty($responsePayload)) {
    //         return $responsePayload;
    //     }
    // }

    // /**
    //  * View tags for an organization.
    //  *
    //  * @param int $id The ID of the organization.
    //  * @return \Cake\Http\Response|null The response payload.
    //  */
    // public function viewTags(int $id)
    // {
    //     $this->CRUD->viewTags($id);
    //     $responsePayload = $this->CRUD->getResponsePayload();
    //     if (!empty($responsePayload)) {
    //         return $responsePayload;
    //     }
    // }
}
