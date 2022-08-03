<div id="workflow-info-modal" class="modal modal-lg hide fade">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h2><?= __('Workflows documentation & concepts') ?></h2>
    </div>
    <div class="modal-body modal-body-xl">
        <ul class="nav nav-tabs">
            <li class="active"><a href=" #modal-info-concept" data-toggle="tab"><?= __('Terminology & Concepts') ?></a></li>
            <li class=""><a href=" #modal-hash-path" data-toggle="tab"><?= __('Hash Path') ?></a></li>
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

            <div class="tab-pane" id="modal-blueprint">
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