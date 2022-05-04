<?php
function buildExecutionPathHTML($executionPathHTML, $nodes, $viewBuilder, $first = false, $depth = 1, $inline = false)
{
    $executionPathHTML = '';
    foreach ($nodes as $i => $node) {
        $executionPathHTML .= sprintf(
            '<div style="display: %s;">%s%s',
            $inline ? 'inline-block' : 'block',
            $first ? '' : sprintf('<i class="%s %s" style="margin-top: 10px; margin-left: 3px; margin-right: 3px;"></i>', $inline ? '' : 'fa-rotate-90', $viewBuilder->FontAwesome->getClass($inline ? 'long-arrow-alt-right' : 'level-up-alt')),
            $viewBuilder->element('Workflows/executionPathNode', ['node' => $node])
        );
        if (!empty($node['next'])) {
            if (count($node['next']) == 1) {
                $executionPathHTML .= sprintf('<span>%s</span>', buildExecutionPathHTML($executionPathHTML, $node['next'], $viewBuilder, false, $depth + 1, true));
            } else {
                $executionPathHTML .= sprintf('<div style="margin-left: %spx">%s</div>', $depth * 20, buildExecutionPathHTML($executionPathHTML, $node['next'], $viewBuilder, false, $depth + 1, false));
            }
        }
        $executionPathHTML .= '</div>';
    }
    return $executionPathHTML;
}
$executionPathHTML = buildExecutionPathHTML('', $execution_path, $this, true, 1);

echo $this->element('genericElements/assetLoader', [
    'js' => ['d3'],
]);
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Workflow view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('Name'),
                'path' => 'Workflow.name'
            ],
            [
                'key' => __('ID'),
                'path' => 'Workflow.id'
            ],
            [
                'key' => __('UUID'),
                'path' => 'Workflow.uuid'
            ],
            [
                'key' => __('Timestamp'),
                'path' => 'Workflow.timestamp',
            ],
            [
                'key' => __('Owner Organisation'),
                'path' => 'Workflow.org_id',
                'pathName' => 'Organisation.name',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Description'),
                'path' => 'Workflow.description'
            ],
            [
                'key' => __('Execution Path'),
                'raw' => $executionPathHTML,
            ],
            [
                'key' => __('Data'),
                'class' => 'restrict-height',
                'path' => 'Workflow.data',
                'type' => 'json',
            ],
        ],
    ]
);
?>

<style>
    .sidebar-workflow-block {
        display: inline-block;
        background-color: #fff;
        border-radius: 5px;
        margin: 0.25em 0.5em;
        padding: 0.25em;
        box-shadow: 0px 3px 6px 2px #33333311;
    }

    .restrict-height>.json_container_Data {
        height: 30vh;
        overflow: auto;
        resize: both;
    }
</style>