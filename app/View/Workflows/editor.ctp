<?php
$blocks_trigger = [
    [
        'id' => 'publish',
        'name' => 'Publish',
        'icon' => 'upload',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'inputs' => 0,
    ],
    [
        'id' => 'new-attribute',
        'name' => 'New Attribute',
        'icon' => 'cube',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'inputs' => 0,
        'disabled' => true,
    ],
    [
        'id' => 'new-object',
        'name' => 'New Object',
        'icon' => 'cubes',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'inputs' => 0,
        'disabled' => true,
    ],
    [
        'id' => 'email-sent',
        'name' => 'Email sent',
        'icon' => 'envelope',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'inputs' => 0,
        'disabled' => true,
    ],
    [
        'id' => 'user-new',
        'name' => 'New User',
        'icon' => 'user-plus',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'inputs' => 0,
        'disabled' => true,
    ],
    [
        'id' => 'feed-pull',
        'name' => 'Feed pull',
        'icon' => 'arrow-alt-circle-down',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'inputs' => 0,
        'disabled' => true,
    ],
];

$blocks_condition = [
    [
        'id' => 'if',
        'name' => 'IF',
        'icon' => 'code-branch',
        'description' => 'IF conditions',
        'outputs' => 2,
        'html_template' => 'IF',
    ],
];

$blocks_action = [
    [
        'id' => 'add-tag',
        'name' => 'Add Tag',
        'icon' => 'tag',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'params' => [
            [
                'type' => 'input',
                'label' => 'Tag name',
                'default' => 'tlp:red',
                'placeholder' => __('Enter tag name')
            ],
        ],
        'outputs' => 0,
    ],
    [
        'id' => 'enrich-attribute',
        'name' => 'Enrich Attribute',
        'icon' => 'asterisk',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'outputs' => 0,
    ],
    [
        'id' => 'slack-message',
        'name' => 'Slack Message',
        'icon' => 'slack',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'params' => [
            [
                'type' => 'select',
                'label' => 'Channel name',
                'default' => 'team-4_3_misp',
                'options' => [
                    'team-4_3_misp',
                    'team-4_0_elite_as_one',
                ],
            ],
        ],
        'outputs' => 0,
    ],
    [
        'id' => 'send-email',
        'name' => 'Send Email',
        'icon' => 'envelope',
        'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
        'params' => [
            [
                'type' => 'select',
                'label' => 'Email template',
                'default' => 'default',
                'options' => [
                    'default',
                    'TLP marking',
                ],
            ],
        ],
        'outputs' => 0,
    ],
    [
        'name' => 'Do nothing',
        'id' => 'dev-null',
        'icon' => 'ban',
        'description' => 'Essentially a /dev/null',
        'outputs' => 0,
    ],
    [
        'name' => 'Push to ZMQ',
        'id' => 'push-zmq',
        'icon' => 'wifi',
        'icon_class' => 'fa-rotate-90',
        'description' => 'Push to the ZMQ channel',
        'params' => [
            [
                'type' => 'input',
                'label' => 'ZMQ Topic',
                'default' => 'from-misp-workflow',
            ],
        ],
        'outputs' => 0,
    ],
];

$blocks_all = array_merge($blocks_trigger, $blocks_condition, $blocks_action);
$workflows = [
    ['id' => 1, 'name' => 'Publish workflow', 'data' => []],
    ['id' => 2, 'name' => 'My test worklow1', 'data' => []],
];
?>

<div class="root-container">
    <div class="main-container">
        <div class="side-panel">
            <h2>Workflows</h2>
            <div class="workflow-selector-container">
                <select type="text" placeholder="Load a workflow" class="chosen-container workflows" autocomplete="off">
                    <?php foreach ($workflows as $workflow) : ?>
                        <option val="<?= h($workflow['name']) ?>"><?= h($workflow['name']) ?></option>
                    <?php endforeach; ?>
                </select>
                <div class="btn-group" style="margin-left: 3px;">
                    <a class="btn btn-primary" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('plus') ?>"></i> <?= __('New') ?></a>
                    <a class="btn btn-primary dropdown-toggle" data-toggle="dropdown" href="#"><span class="caret"></span></a>
                    <ul class="dropdown-menu">
                        <li><a href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-export') ?>"></i> <?= __('Export workflow') ?></a></li>
                        <li><a href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('file-import') ?>"></i> <?= __('Import workflow') ?></a></li>
                    </ul>
                </div>
            </div>
            <div class="" style="margin-left: 3px;">
                <a class="btn btn-primary" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('save') ?>"></i> <?= __('Save') ?></a>
                <a class="btn btn-danger" href="#"><i class="fa-fw <?= $this->FontAwesome->getClass('trash') ?>"></i> <?= __('Delete') ?></a>
            </div>

            <h2>Blocks</h2>
            <select type="text" placeholder="Search for a block" class="chosen-container blocks" autocomplete="off">
                <?php foreach ($blocks_all as $block) : ?>
                    <option val="<?= h($block['name']) ?>"><?= h($block['name']) ?></option>
                <?php endforeach; ?>
            </select>

            <ul class="nav nav-tabs" id="block-tabs">
                <li class="active"><a href="#container-triggers">
                        <i class="<?= $this->FontAwesome->getClass('flag') ?>"></i>
                        Triggers
                    </a></li>
                <li><a href="#container-conditions">
                        <i class="<?= $this->FontAwesome->getClass('code-branch') ?>"></i>
                        conditions
                    </a></li>
                <li><a href="#container-actions">
                        <i class="<?= $this->FontAwesome->getClass('play') ?>"></i>
                        Actions
                    </a></li>
            </ul>

            <div class="tab-content">
                <div class="tab-pane active" id="container-triggers">
                    <?php foreach ($blocks_trigger as $block) : ?>
                        <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                    <?php endforeach; ?>
                </div>
                <div class="tab-pane" id="container-conditions">
                    <?php foreach ($blocks_condition as $block) : ?>
                        <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                    <?php endforeach; ?>
                </div>
                <div class="tab-pane" id="container-actions">
                    <?php foreach ($blocks_action as $block) : ?>
                        <?= $this->element('Workflows/sidebar-block', ['block' => $block]) ?>
                    <?php endforeach; ?>
                </div>
            </div>

        </div>
        <div class="canvas">
            <div id="drawflow"></div>
        </div>
    </div>
    <div class="properties-container">

    </div>
</div>

<div id="block-modal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3>Block options</h3>
    </div>
    <div class="modal-body">
        <p>One fine body…</p>
    </div>
    <div class="modal-footer">
        <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
        <button class="btn btn-primary">Save changes</button>
    </div>
</div>
<script src="https://code.jquery.com/ui/1.13.1/jquery-ui.js"></script>

<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['drawflow.min'],
    'js' => ['jquery-ui', 'drawflow.min', 'doT'],
]);
echo $this->element('genericElements/assetLoader', [
    'css' => ['workflows-editor'],
    'js' => ['workflows-editor/workflows-editor'],
]);
?>

<script>
    var $root_container = $('.root-container')
    var $side_panel = $('.root-container .side-panel')
    var $canvas = $('.root-container .canvas')
    var $chosenWorkflows = $('.root-container .side-panel .chosen-container.workflows')
    var $chosenBlocks = $('.root-container .side-panel .chosen-container.blocks')
    var $drawflow = $('#drawflow')
    var editor = false
    var all_blocks = <?= json_encode($blocks_all) ?>;

    $(document).ready(function() {
        initDrawflow()
    })
</script>