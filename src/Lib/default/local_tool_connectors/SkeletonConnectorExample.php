<?php
// set a namespace for the module
namespace SkeletonConnector;

// These can be left as is. We want to have access to the commonconnector tools as well as basic http / exception functions
require_once(ROOT . '/src/Lib/default/local_tool_connectors/CommonConnectorTools.php');
use CommonConnectorTools\CommonConnectorTools;
use Cake\Http\Client;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Client\Response;

class SkeletonConnector extends CommonConnectorTools
{

    /*
     *
     * ====================================== Metainformation block ======================================
     *
     */
    public $description = '';
    public $connectorName = 'SkeletonConnector';
    public $name = 'Skeleton';
    public $version = '0.1';

    // exposed function list and configuration
    public $exposedFunctions = [
        'myIndexAction' => [
            'type' => 'index',
            'scope' => 'child',
            'params' => [
                'quickFilter',
                'sort',
                'direction',
                'page',
                'limit'
            ]
        ],
        'myFormAction' => [
            'type' => 'formAction',
            'scope' => 'childAction',
            'params' => [
                'setting',
                'value'
            ],
            'redirect' => 'serverSettingsAction'
        ]
    ];
    public $settings = [
        'url' => [
            'type' => 'text'
        ],
        'authkey' => [
            'type' => 'text'
        ],
        'skip_ssl' => [
            'type' => 'boolean'
        ],
    ];
    public $settingsPlaceholder = [
        'url' => 'https://your.url',
        'authkey' => '',
        'skip_ssl' => '0',
    ];

    public function health(Object $connection): array
    {
        /*
            returns an array with 2 keys:
            [
                status: the numeric response code (0: UNKNOWN, 1: OK, 2: ISSUES, 3: ERROR),
                message: status message shown
            ]
        */
        return $health;
    }

    /*
     *
     * ====================================== Exposed custom functions ======================================
     *
     */

    public function myIndexAction(array $params): array
    {
        // $data = get data from local tool

        //if we want to filter it via the quicksearch
        if (!empty($params['quickFilter'])) {
            // filter $data
        }

        // return the data embedded in a generic index parameter array

        return [
            'type' => 'index',
            'title' => false,
            'description' => false,
            'data' => [
                'data' => $data,
                'skip_pagination' => 1,
                'top_bar' => [
                    'children' => [
                        [
                            'type' => 'search',
                            'button' => __('Search'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'value',
                            'additionalUrlParams' => $urlParams
                        ]
                    ]
                ],
                'fields' => [
                    [
                        'name' => 'field1_name',
                        'sort' => 'field1.path',
                        'data_path' => 'field1.path',
                    ]
                ],
                'pull' => 'right',
                'actions' => [
                    [
                        'open_modal' => '/localTools/action/' . h($params['connection']['id']) . '/myForm?myKey={{0}}',
                        'modal_params_data_path' => ['myKey'],
                        'icon' => 'font_awesome_icon_name',
                        'reload_url' => '/localTools/action/' . h($params['connection']['id']) . '/myIndex'
                    ]
                ]
            ]
        ];
    }


    public function myFormAction(array $params): array
    {
        if ($params['request']->is(['get'])) {
            return [
                'data' => [
                    'title' => __('My Form Title'),
                    'description' => __('My form description'),
                    'submit' => [
                        'action' => $params['request']->getParam('action')
                    ],
                    'url' => ['controller' => 'localTools', 'action' => 'action', h($params['connection']['id']), 'myFormAction']
                ]
            ];
        } elseif ($params['request']->is(['post'])) {
            // handle posted data
            if ($success) {
                return ['success' => 1, 'message' => __('Action successful.')];
            } else {
                return ['success' => 0, 'message' => __('Action failed spectacularly.')];
            }
        }
        throw new MethodNotAllowedException(__('Invalid http request type for the given action.'));
    }

    /*
     *
     * ====================================== Inter connection functions ======================================
     *
     */

    public function initiateConnection(array $params): array
    {
        // encode initial connection in local tool
        // build and return initiation payload
        return $payload;
    }

    public function acceptConnection(array $params): array
    {
        // encode acceptance of the connection request in local tool, based on the payload from the initiation
        // return payload for remote to encode the connection
        return $payload;
    }

    public function finaliseConnection(array $params): bool
    {
        // based on the payload from the acceptance, finalise the connection
        // return true on success
        return $success;
    }
}

 ?>
