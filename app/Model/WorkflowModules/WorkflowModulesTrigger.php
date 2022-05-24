<?php
include_once 'WorkflowModules.php';

class WorkflowModulesTrigger extends WorkflowModules
{
    protected function loadModules(): array
    {
        return [
            [
                'id' => 'publish',
                'name' => 'Publish',
                'icon' => 'upload',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'outputs' => 2,
            ],
            [
                'id' => 'new-attribute',
                'name' => 'New Attribute',
                'icon' => 'cube',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                // 'disabled' => true,
                'outputs' => 2,
            ],
            [
                'id' => 'new-object',
                'name' => 'New Object',
                'icon' => 'cubes',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
                'outputs' => 2,
            ],
            [
                'id' => 'email-sent',
                'name' => 'Email sent',
                'icon' => 'envelope',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
            ],
            [
                'id' => 'user-new',
                'name' => 'New User',
                'icon' => 'user-plus',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
                'outputs' => 2,
            ],
            [
                'id' => 'feed-pull',
                'name' => 'Feed pull',
                'icon' => 'arrow-alt-circle-down',
                'description' => 'Lorem ipsum dolor, sit amet consectetur adipisicing elit.',
                'module_type' => 'trigger',
                'inputs' => 0,
                'disabled' => true,
            ],
        ];
    }
}