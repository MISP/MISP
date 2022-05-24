<?php
include_once 'WorkflowModules.php';

class WorkflowModulesLogic extends WorkflowModules
{
    protected function loadModules(): array
    {
        return [
            [
                'id' => 'if',
                'name' => 'IF',
                'icon' => 'code-branch',
                'description' => 'Simple IF / ELSE condition block. Use the `then` output for execution path satifying the conditions passed to the `IF` block.',
                'module_type' => 'logic',
                'outputs' => 2,
                'html_template' => 'IF',
                'params' => [
                    [
                        'type' => 'textarea',
                        'label' => 'Event Conditions',
                        'default' => '',
                        'placeholder' => '{ "tags" : { "AND" : [ "tlp : green" , "Malware" ] , "NOT" : [ "%ransomware%" ]}}'
                    ],
                ],
            ],
            [
                'id' => 'parallel-task',
                'name' => 'Parallel Task',
                'icon' => 'random',
                'description' => 'Allow breaking the execution process and running parallel tasks. You can connect multiple blocks the `parallel` output.',
                'module_type' => 'logic',
                'outputs' => 1,
                'html_template' => 'parallel',
                'params' => [],
            ],
        ];
    }
}
