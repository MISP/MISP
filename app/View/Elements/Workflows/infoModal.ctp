<div id="workflow-info-modal" class="modal modal-lg hide fade">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h2><?= __('Workflows documentation & concepts') ?></h2>
    </div>
    <div class="modal-body modal-body-xl">
        <ul class="nav nav-tabs">
            <li class="active"><a href=" #modal-info-concept" data-toggle="tab"><?= __('Terminology & Concepts') ?></a></li>
            <li class=""><a href=" #modal-hash-path" data-toggle="tab"><?= __('Hash Path') ?></a></li>
            <li class=""><a href=" #modal-core-format" data-toggle="tab"><?= __('MISP Core Format') ?></a></li>
            <li class=""><a href=" #modal-jinja2" data-toggle="tab"><?= __('Jinja2 Syntax') ?></a></li>
            <li class=""><a href=" #modal-blueprint" data-toggle="tab"><?= __('Blueprints') ?></a></li>
            <li class=""><a href=" #modal-debugging" data-toggle="tab"><?= __('Debugging') ?></a></li>
            <li><a href="#modal-info-usage" data-toggle="tab"><?= __('Usage & Shortcuts') ?></a></li>
        </ul>
        <div class="tab-content">
            <div class="tab-pane active" id="modal-info-concept">
                <h1><?= __('Terminology') ?></h1>
                <ul>
                    <li><strong><?= __('Workflow Execution path:') ?></strong> <?= __('A path composed of actions to be executed sequentially. A workflow can have multiple execution paths if it has condition modules') ?></li>
                    <li><strong><?= __('Trigger:') ?></strong> <?= __('Starting point of an execution path. Triggers are called when specific actions happened in MISP like Event publishing or data creation.') ?></li>
                    <li><strong><?= __('Condition module:') ?></strong> <?= __('Special type of module that can hange the the execution path. An IF module can produce two execution paths, one if the condition is satisfied and another one if it isn\'t.') ?></li>
                    <li><strong><?= __('Action module:') ?></strong> <?= __('Module that are executed that can additional actions than the default MISP behavior.') ?></li>
                    <li><strong><?= __('Blueprints:') ?></strong> <?= __('Saved collection of modules that can be re-used and shared.') ?></li>
                    <li><strong><?= __('MISP Core format:') ?></strong> <?= __('Standardized format specification used in MISP. Also called MISP standard, the %s is currently an RFC draft.', sprintf('<a href="%s" target="_blank">%s</a>', __('MISP Core format'), 'https://github.com/MISP/misp-rfc')) ?></li>
                    <li><strong><?= __('Concurrent task module:') ?></strong> <?= __('Special type of logic module allowing to branch off the current execution path. The remaining execution path will be executed later on by a worker.') ?></li>
                    <ul>
                        <li><?= __('For example, the blocking `Event publish` workflow can prevent the publishing.') ?></li>
                    </ul>
                    <li><strong><?= __('Blocking module:') ?></strong> <?= __('Blocking modules are action modules having the ability to make blocking workflows to block the current action. Blocking modules on non-blocking workflows have no effect on the blocking aspect.') ?></li>
                    <li><strong><?= __('Module Filtering Conditions:') ?></strong> <?= __('Some action modules accept filtering condition. This basic filtering allows user to specify on which part of the data the module should be executed.') ?></li>
                    <ul>
                        <li><?= __('For example, the enrich-event module can only perform the enrichment on Attributes matching the condition.') ?></li>
                    </ul>
                </ul>
                <h1><?= __('Concepts') ?></h1>
                <h2>
                    <span class="label label-important" style="line-height: 20px; vertical-align: middle;" title="<?= __('This workflow is a blocking worklow and can prevent the default MISP behavior to execute') ?>">
                        <i class="fa-lg fa-fw <?= $this->FontAwesome->getClass('stop-circle') ?>"></i>
                        <?= __('Blocking') ?>
                    </span>
                    <?= __('and') ?>
                    <span class="label label-success" style="line-height: 20px; vertical-align: middle;" title="<?= __('This workflow is a not blocking worklow. The default MISP behavior will or has already happened') ?>">
                        <i class="fa-lg fa-fw <?= $this->FontAwesome->getClass('check-circle') ?>"></i>
                        <?= __('Non blocking') ?>
                    </span>
                    <?= __('Workflows') ?>
                </h2>
                <p><?= __('Workflow can either be a blocking or non-blocking workflow. Blocking workflows are able to stop the default MISP behavior of the current action in contrast to non-blocking workflows.') ?></p>
                <p><strong><?= __('Example:') ?></strong></p>
                <ol>
                    <li><?= __('An Event gets published') ?></li>
                    <li><?= __('The blocking `publish` workflow is called') ?></li>
                    <li><?= __('If a blocking module like the `stop-execution` module blocks the execution, the event will not be published') ?></li>
                </ol>
                <h2>
                    <i title="<?= __('This module can block execution') ?>" class="text-error fa-fw <?= $this->FontAwesome->getClass('stop-circle') ?>"></i>
                    <?= __('Blocking modules') ?>
                </h2>
                <p><?= __('Blocking modules are action modules having the ability to make blocking workflows block the current action. Blocking modules being executed in a non-blocking workflow have no effect on the blocking aspect.') ?></p>

                <h2>
                    <?= __('Logic Module: %s Concurrent Task', sprintf('<i class="%s fa-fw"></i>', $this->FontAwesome->getClass('random'))) ?>
                </h2>
                <p><?= __('Allowing breaking the execution flow into a concurrent tasks to be executed later on by a background worker, thus preventing blocking module to cancel the ongoing operation.') ?></p>

                <h2><?= __('Workflow execution context') ?></h2>
                <ul>
                    <li><?= __('Workflows can be triggered by any users') ?></li>
                    <li><?= __('However, the user for which the workflow executes has the site-admin role and is from the MISP.host_org_id') ?></li>
                </ul>
            </div>

            <div class="tab-pane" id="modal-hash-path">
                <h2><?= __('Hash path filtering') ?></h2>
                <p><?= __('Some modules have the possibility to filter or check conditions using %s', sprintf('<a href="%s">%s</a>', 'https://book.cakephp.org/2/en/core-utility-libraries/hash.html', __('CakePHP\'s path expression.'))) ?></p>
                <p><i class="fa-fw <?= $this->FontAwesome->getClass('exclamation-triangle') ?>"></i> <?= __('Note that using filters will not modify the data being passed on from module to module.') ?></p>
                <p><strong><?= __('Example:') ?></strong></p>
                <p><?= __('The passed condition to the module is the following: ') ?></p>
                <pre>'{n}[name=fred].id'</pre>
                <pre>
$users = [
     ['id' => 123, 'name'=> 'fred', 'surname' => 'bloggs'],
     ['id' => 245, 'name' => 'fred', 'surname' => 'smith'],
     ['id' => 356, 'name' => 'joe', 'surname' => 'smith'],
];
$path_expression = '{n}[name=fred].id'
$ids = Hash::extract($users, $path_expression);
// $ids will be [123, 245]</pre>

                <h3><?= __('Logic module with hash path') ?></h3>
                <p><?= __('The `IF :: Generic` module allows to direct the execution path based on the provided condition. If the encoded condition is satisfied, the execution path will take the `then` path. Otherwise, the `else` path will be used.') ?></p>
                <p><i class="fa-fw <?= $this->FontAwesome->getClass('exclamation-triangle') ?>"></i> <?= __('Note that the condition is only evaluated once.') ?></p>
                <p><strong><?= __('Example:') ?></strong></p>
                <pre>
$value_passed_to_if_module = 'fred'
$operator_passed_to_if_module = In'
$path_expression_passed_to_if_module = '{n}.name'
$data_passed_to_if_module = [
     ['id' => 123, 'name'=> 'fred', 'surname' => 'bloggs'],
     ['id' => 245, 'name' => 'fred', 'surname' => 'smith'],
     ['id' => 356, 'name' => 'joe', 'surname' => 'smith'],
];
// The condition is satisfied as `fred` is contained in the extracted data.
// Then `then` branch will be used by the execution path</pre>
            </div>

            <div class="tab-pane" id="modal-core-format">
                <h2><?= __('MISP Core Format') ?></h2>
                <h4><?= __('Accessing Attributes') ?></h4>
                <p><?= __('There are two ways to access attributes') ?></p>
                <ul>
                    <li><?= sprintf('%s <code>%s</code> %s', __('Use the'), 'Attribute', __('key to access only attributes')) ?></li>
                    <li><?= sprintf('%s <code>%s</code> %s', __('Use the'), '_AttributeFlattened', __('key to access all attributes including Object Attributes')) ?></li>
                </ul>
                <p><strong><?= __('Example:') ?></strong></p>
                <pre>Event._AttributeFlattened.{n}</pre>

                <h4><?= __('Getting all tag names attached an Attribute only') ?></h4>
                <ul>
                    <li><?= __('First, we access the Attributes with ') ?> <code>Event.Attribute.{n}</code></li>
                    <li><?= __('Then, we access all tags with ') ?> <code>Tag.{n}.name</code></li>
                </ul>
                <p><strong><?= __('Full example:') ?></strong></p>
                <pre>Event._AttributeFlattened.{n}.Tag.{n}.name</pre>

                <h4><?= __('MISP Core Format Sample') ?></h4>
                <ul>
                    <li><?= __('Attributes are always encapsulated in the Event or Object') ?></li>
                    <li><?= __('Additional key') ?> <code>_AttributeFlattened</code> containing all Attributes</li>
                    <li><?= __('Additional key') ?> <code>_allTags</code> containing all tags</li>
                    <ul>
                        <li><?= __('Additional key %s for Tags', '<code>inherited</code>') ?></li>
                    </ul>
                </ul>
                <p><strong><?= __('Sample:') ?></strong></p>
                <pre id="misp-core-format-sample">
{
    "Event": {
        "id": "64",
        "orgc_id": "1",
        "org_id": "1",
        "date": "2023-05-03",
        "threat_level_id": "1",
        "info": "Core format sample",
        "published": false,
        "uuid": "b9557473-bb46-4c65-b69e-974b3c93c1f4",
        "attribute_count": "2",
        "analysis": "0",
        "timestamp": "1683117902",
        "distribution": "1",
        "proposal_email_lock": false,
        "locked": false,
        "publish_timestamp": "0",
        "sharing_group_id": "0",
        "disable_correlation": false,
        "extends_uuid": "",
        "protected": null,
        "event_creator_email": "admin@admin.test",
        "Org": {
            "id": "1",
            "name": "ORGNAME",
            "uuid": "c5de83b4-36ba-49d6-9530-2a315caeece6",
            "local": true
        },
        "Orgc": {
            "id": "1",
            "name": "ORGNAME",
            "uuid": "c5de83b4-36ba-49d6-9530-2a315caeece6",
            "local": true
        },
        "Attribute": [
            {
                "id": "1695",
                "type": "ip-src",
                "category": "Network activity",
                "to_ids": true,
                "uuid": "9ac36927-d874-4094-bf4c-f922c1e9cc35",
                "event_id": "64",
                "distribution": "5",
                "timestamp": "1683117902",
                "comment": "",
                "sharing_group_id": "0",
                "deleted": false,
                "disable_correlation": false,
                "object_id": "0",
                "object_relation": null,
                "first_seen": null,
                "last_seen": null,
                "value": "8.8.8.8",
                "Galaxy": [],
                "ShadowAttribute": [],
                "Tag": [
                    {
                        "id": "137",
                        "name": "PAP:AMBER",
                        "colour": "#ffa800",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": false,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null
                    }
                ],
                "_allTags": [
                    {
                        "id": "299",
                        "name": "misp-galaxy:country=\"belgium\"",
                        "colour": "#0088cc",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": true,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": true
                    },
                    {
                        "id": "79",
                        "name": "tlp:green",
                        "colour": "#339900",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": false,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": true
                    },
                    {
                        "id": "137",
                        "name": "PAP:AMBER",
                        "colour": "#ffa800",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": false,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": false
                    }
                ],
                "enrichment": [
                    {}
                ]
            }
        ],
        "ShadowAttribute": [],
        "RelatedEvent": [
            {
                "Event": {
                    "id": "43",
                    "date": "2022-12-15",
                    "threat_level_id": "1",
                    "info": "Fake event WF",
                    "published": false,
                    "uuid": "3a928b41-a9ec-4252-ab9f-d1859dbfc14a",
                    "analysis": "0",
                    "timestamp": "1683116434",
                    "distribution": "1",
                    "org_id": "1",
                    "orgc_id": "1",
                    "Org": {
                        "id": "1",
                        "name": "ORGNAME",
                        "uuid": "c5de83b4-36ba-49d6-9530-2a315caeece6"
                    },
                    "Orgc": {
                        "id": "1",
                        "name": "ORGNAME",
                        "uuid": "c5de83b4-36ba-49d6-9530-2a315caeece6"
                    }
                }
            }
        ],
        "Galaxy": [
            {
                "id": "4",
                "uuid": "84668357-5a8c-4bdd-9f0f-6b50b2aee4c1",
                "name": "Country",
                "type": "country",
                "description": "Country meta information based on the database provided by geonames.org.",
                "version": "1",
                "icon": "globe",
                "namespace": "misp",
                "enabled": true,
                "local_only": false,
                "GalaxyCluster": [
                    {
                        "id": "1703",
                        "uuid": "84668357-5a8c-4bdd-9f0f-6b50b242454c",
                        "collection_uuid": "84668357-5a8c-4bdd-9f0f-6b50b2aee4c1",
                        "type": "country",
                        "value": "belgium",
                        "tag_name": "misp-galaxy:country=\"belgium\"",
                        "description": "Belgium",
                        "galaxy_id": "4",
                        "source": "MISP Project",
                        "authors": [
                            "geonames.org"
                        ],
                        "version": "1",
                        "distribution": "3",
                        "sharing_group_id": null,
                        "org_id": "0",
                        "orgc_id": "0",
                        "default": true,
                        "locked": false,
                        "extends_uuid": "",
                        "extends_version": "0",
                        "published": false,
                        "deleted": false,
                        "GalaxyClusterRelation": [],
                        "Org": {
                            "id": "0",
                            "name": "MISP",
                            "date_created": "",
                            "date_modified": "",
                            "description": "Automatically generated MISP organisation",
                            "type": "",
                            "nationality": "Not specified",
                            "sector": "",
                            "created_by": "0",
                            "uuid": "0",
                            "contacts": "",
                            "local": true,
                            "restricted_to_domain": [],
                            "landingpage": null
                        },
                        "Orgc": {
                            "id": "0",
                            "name": "MISP",
                            "date_created": "",
                            "date_modified": "",
                            "description": "Automatically generated MISP organisation",
                            "type": "",
                            "nationality": "Not specified",
                            "sector": "",
                            "created_by": "0",
                            "uuid": "0",
                            "contacts": "",
                            "local": true,
                            "restricted_to_domain": [],
                            "landingpage": null
                        },
                        "meta": {
                            "Capital": [
                                "Brussels"
                            ],
                            "Continent": [
                                "EU"
                            ],
                            "CurrencyCode": [
                                "EUR"
                            ],
                            "CurrencyName": [
                                "Euro"
                            ],
                            "ISO": [
                                "BE"
                            ],
                            "ISO3": [
                                "BEL"
                            ],
                            "Languages": [
                                "nl-BE,fr-BE,de-BE"
                            ],
                            "Population": [
                                "10403000"
                            ],
                            "tld": [
                                ".be"
                            ]
                        },
                        "tag_id": 299,
                        "event_tag_id": "380",
                        "local": false,
                        "relationship_type": false
                    }
                ]
            }
        ],
        "Object": [
            {
                "id": "111",
                "name": "url",
                "meta-category": "network",
                "description": "url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.",
                "template_uuid": "60efb77b-40b5-4c46-871b-ed1ed999fce5",
                "template_version": "9",
                "event_id": "64",
                "uuid": "384ebae1-c97d-48a4-9efb-94a945c4860f",
                "timestamp": "1683117902",
                "distribution": "5",
                "sharing_group_id": "0",
                "comment": "",
                "deleted": false,
                "first_seen": null,
                "last_seen": null,
                "ObjectReference": [],
                "Attribute": [
                    {
                        "id": "1696",
                        "type": "url",
                        "category": "Network activity",
                        "to_ids": true,
                        "uuid": "a915bbbe-2639-4d9b-83a2-abd58b8e5498",
                        "event_id": "64",
                        "distribution": "5",
                        "timestamp": "1683117902",
                        "comment": "",
                        "sharing_group_id": "0",
                        "deleted": false,
                        "disable_correlation": false,
                        "object_id": "111",
                        "object_relation": "url",
                        "first_seen": null,
                        "last_seen": null,
                        "value": "https://www.misp-project.org/",
                        "Galaxy": [],
                        "ShadowAttribute": [],
                        "_allTags": [
                            {
                                "id": "299",
                                "name": "misp-galaxy:country=\"belgium\"",
                                "colour": "#0088cc",
                                "exportable": true,
                                "user_id": "0",
                                "hide_tag": false,
                                "numerical_value": null,
                                "is_galaxy": true,
                                "is_custom_galaxy": false,
                                "local_only": false,
                                "local": 0,
                                "relationship_type": null,
                                "inherited": true
                            },
                            {
                                "id": "79",
                                "name": "tlp:green",
                                "colour": "#339900",
                                "exportable": true,
                                "user_id": "0",
                                "hide_tag": false,
                                "numerical_value": null,
                                "is_galaxy": false,
                                "is_custom_galaxy": false,
                                "local_only": false,
                                "local": 0,
                                "relationship_type": null,
                                "inherited": true
                            }
                        ]
                    }
                ]
            }
        ],
        "EventReport": [],
        "CryptographicKey": [],
        "Tag": [
            {
                "id": "299",
                "name": "misp-galaxy:country=\"belgium\"",
                "colour": "#0088cc",
                "exportable": true,
                "user_id": "0",
                "hide_tag": false,
                "numerical_value": null,
                "is_galaxy": true,
                "is_custom_galaxy": false,
                "local_only": false,
                "local": 0,
                "relationship_type": null
            },
            {
                "id": "79",
                "name": "tlp:green",
                "colour": "#339900",
                "exportable": true,
                "user_id": "0",
                "hide_tag": false,
                "numerical_value": null,
                "is_galaxy": false,
                "is_custom_galaxy": false,
                "local_only": false,
                "local": 0,
                "relationship_type": null
            }
        ],
        "_AttributeFlattened": [
            {
                "id": "1695",
                "type": "ip-src",
                "category": "Network activity",
                "to_ids": true,
                "uuid": "9ac36927-d874-4094-bf4c-f922c1e9cc35",
                "event_id": "64",
                "distribution": "5",
                "timestamp": "1683117902",
                "comment": "",
                "sharing_group_id": "0",
                "deleted": false,
                "disable_correlation": false,
                "object_id": "0",
                "object_relation": null,
                "first_seen": null,
                "last_seen": null,
                "value": "8.8.8.8",
                "Galaxy": [],
                "ShadowAttribute": [],
                "Tag": [
                    {
                        "id": "137",
                        "name": "PAP:AMBER",
                        "colour": "#ffa800",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": false,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null
                    }
                ],
                "_allTags": [
                    {
                        "id": "299",
                        "name": "misp-galaxy:country=\"belgium\"",
                        "colour": "#0088cc",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": true,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": true
                    },
                    {
                        "id": "79",
                        "name": "tlp:green",
                        "colour": "#339900",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": false,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": true
                    },
                    {
                        "id": "137",
                        "name": "PAP:AMBER",
                        "colour": "#ffa800",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": false,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": false
                    }
                ],
                "enrichment": [
                    {}
                ]
            },
            {
                "id": "1696",
                "type": "url",
                "category": "Network activity",
                "to_ids": true,
                "uuid": "a915bbbe-2639-4d9b-83a2-abd58b8e5498",
                "event_id": "64",
                "distribution": "5",
                "timestamp": "1683117902",
                "comment": "",
                "sharing_group_id": "0",
                "deleted": false,
                "disable_correlation": false,
                "object_id": "111",
                "object_relation": "url",
                "first_seen": null,
                "last_seen": null,
                "value": "https://www.misp-project.org/",
                "Galaxy": [],
                "ShadowAttribute": [],
                "_allTags": [
                    {
                        "id": "299",
                        "name": "misp-galaxy:country=\"belgium\"",
                        "colour": "#0088cc",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": true,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": true
                    },
                    {
                        "id": "79",
                        "name": "tlp:green",
                        "colour": "#339900",
                        "exportable": true,
                        "user_id": "0",
                        "hide_tag": false,
                        "numerical_value": null,
                        "is_galaxy": false,
                        "is_custom_galaxy": false,
                        "local_only": false,
                        "local": 0,
                        "relationship_type": null,
                        "inherited": true
                    }
                ]
            }
        ]
    }
}
</pre>

            </div>

            <div class="tab-pane" id="modal-jinja2">
                <h3>
                    <img src="/img/jinja.png" alt="Jinja icon" width="60" height="26">
                    <?= __('Jinja2 Syntax') ?>
                </h3>
                <p><i class="fa-fw <?= $this->FontAwesome->getClass('exclamation-triangle') ?>"></i> <?= __('For these examples, we consider the module received data under the MISP core format.') ?></p>
                <p><i class="fa-fw <?= $this->FontAwesome->getClass('link') ?>"></i> <?= __('More documenation available on Jinja2 template designer documentation\'s') ?> <a href="https://jinja.palletsprojects.com/en/3.1.x/templates/"><?= __('website') ?></a></p>
                <h4><?= __('You can use the dot <code>`.` </code> notation or the subscript syntax <code>`[]`</code> to access attributes of a variable') ?></h4>
                <ul>
                    <li><code>{{ Event.info }}</code>: <?= __('Shows the title of the event') ?></li>
                    <li><code>{{ Event['info'] }}</code>: <?= __('Shows the title of the event') ?></li>
                </ul>
                <h4><?= __('Jinja2 allows you to easily create list') ?></h4>
                <pre>
{% for attribute in Event.Attribute %}
- {{ attribute.value }}
{% endfor %}
</pre>

                <h4><?= __('Jinja2 allows you to add logic') ?></h4>
                <pre>
{% if "tlp:white" in Event.Tag %}
    - This Event has the TLP:WHITE tag
{% else %}
    - This Event doesn't have the TLP:WHITE tag
{% endif %}
</pre>

                <h4><?= __('Jinja2 allows you to modify variables by using filters') ?></h4>
                <pre>
# The `reverse` filter
- `{{ Event.info | reverse }}`
-> The event title, but reversed

# The `format` filter
- `{{ "%s :: %s" | format(Event.Attribute[0].type, Event.Attribute[0].value) }}`
-> Allow to format string. python `.format()`

# The `groupby` filter
{% for type, attributes in Event.Attribute|groupby("type") %}
- {{ type }}{% for attribute in attributes %}
    - {{ attribute.value }}
    {% endfor %}
{% endfor %}

# The `json` filter
{{ attribute | tojson }}
-> The complete attribute json encoded
</pre>

            </div>

            <div class=" tab-pane" id="modal-blueprint">
                <h3><?= __('Blueprints') ?></h3>
                <ul>
                    <li><?= __('Blueprints allow user to saved a collection of modules and how they are connected together so that they can be re-used and shared.') ?></li>
                    <li><?= __('Blueprints can either come from the `misp-workflow-blueprints` reposity or be imported via the UI or API.') ?></li>
                    <li><?= __('To create a blueprint, use the multi-select tool in the editor then click on the `save blueprint` button.') ?></li>
                    <li><?= __('To include an existing blueprint in the workflow being edited, simply drag the blueprint from the sidebar to the workflow.') ?></li>
                </ul>
            </div>

            <div class="tab-pane" id="modal-debugging">
                <h2><?= __('Debugging Workflows') ?></h2>
                <h4><?= __('Using Log entries') ?></h4>
                <ul>
                    <li><?= __('Workflow execution is logged in the application logs: %s', sprintf('<code>%s</code>', '/admin/logs/index')) ?></li>
                    <li><?= __('Or stored on disk in the following file: %s', sprintf('<code>%s</code>', '/app/tmp/logs/workflow-execution.log')) ?></li>
                </ul>
                <h4><?= __('Using the Debug Mode') ?></h4>
                <span class="btn btn-success" style="margin: 0 1em 0.5em 1em;">
                    <i class="<?= $this->FontAwesome->getClass('bug') ?> fa-fw"></i>
                    <?= __('Debug Mode: ') ?>
                    <b><?= __('On') ?></b>
                </span>
                <ol>
                    <li><?= __('Make sure you have configure the setting: %s', sprintf('<code>%s</code>', 'Plugin.Workflow_debug_url')) ?></li>
                    <li><?= __('Have a webserver listening on the address') ?></li>
                    <li><?= __('Turn the debug mode of the workflow to work on') ?></li>
                    <ul>
                        <li><?= __('For offline testing: %s', sprintf('<code>%s</code>', 'tools/misp-workflows/webhook-listener.py')) ?></li>
                        <li><?= __('For online testing, you can use website such as %s', '<a href="https://requestbin.com" target="_blank">requestbin.com</a>') ?></li>
                    </ul>
                    <li><?= __('Execute the workflow') ?></li>
                </ol>
            </div>

            <div class="tab-pane" id="modal-info-usage">
                <h3><?= __('Shortcuts') ?></h3>
                <table class="table table-condensed">
                    <thead>
                        <tr>
                            <th><?= __('Shortcut') ?></th>
                            <th><?= __('Effect') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><code>Ctrl + Mouse_wheel</code></td>
                            <td> <?= __('Zoom in / out') ?></td>
                        </tr>
                        <tr>
                            <td><code>Shift + Ctrck</code></td>
                            <td> <?= __('Multi-select tool') ?></td>
                        </tr>
                        <tr>
                            <td><code>Ctrl + s</code></td>
                            <td> <?= __('Save workflow') ?></td>
                        </tr>
                        <tr>
                            <td><code>Ctrl + d</code></td>
                            <td> <?= __('Duptrcate selection') ?></td>
                        </tr>
                        <tr>
                            <td><code>delete</code></td>
                            <td> <?= __('Deletion selection') ?></td>
                        </tr>
                        <tr>
                            <td><code>c</code></td>
                            <td> <?= __('Center canvas in viewport') ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="modal-footer">
        <a href="#" class="btn" data-dismiss="modal">Close</a>
    </div>
</div>