<?php
App::uses('AppHelper', 'View/Helper');

/**
 * The add control as a detail view's action card offers it
 * (genericElementsBS5/Cards/card_launch_bar); intel-graph-actions.js runs it.
 */
class IntelGraphHelper extends AppHelper
{
    /**
     * Add to workspace, Remove from workspace (while the workspace holds the
     * record), Add to another collection… and New collection with this….
     *
     * @param array $items The records, as IntelGraph.add() takes them, each with a label
     * @param bool $tile Whether Add to workspace is a tile, with a caret
     *                   offering the others
     * @return array Launch bar actions
     */
    public function launchActions(array $items, $tile = true)
    {
        $json = json_encode(array_values($items));
        $add = [
            'url' => '#',
            'icon' => 'misp-icon misp-icon-analyst-graph misp-simple',
            'label' => __('Add to workspace'),
            'short' => __('Workspace'),
            'entity' => 'analystGraph',
            'attributes' => [
                'data-intel-graph-add' => $json,
                'data-intel-graph-label-in' => __('In workspace ✓ — show in the dock'),
                'data-intel-graph-short-in' => __('Workspace ✓'),
            ],
        ];
        if ($tile) {
            $add['split'] = ['data-intel-graph-split' => ''];
            $add['tick'] = true;
        } else {
            $add['menuOnly'] = true;
        }
        return [
            $add,
            [
                'url' => '#',
                'icon' => 'fas fa-folder-minus',
                'label' => __('Remove from workspace'),
                'entity' => 'analystGraph',
                'menuOnly' => true,
                'attributes' => ['data-intel-graph-remove' => $json, 'data-intel-graph-when' => 'in', 'hidden' => 'hidden', 'data-lb-off' => ''],
            ],
            [
                'url' => '#',
                'icon' => 'fas fa-folder-plus',
                'label' => __('Add to another collection…'),
                'entity' => 'collection',
                'menuOnly' => true,
                'attributes' => ['data-intel-graph-other' => $json],
            ],
            [
                'url' => '#',
                'icon' => 'fas fa-circle-plus',
                'label' => count($items) > 1 ? __('New collection with these…') : __('New collection with this…'),
                'entity' => 'collection',
                'menuOnly' => true,
                'attributes' => ['data-intel-graph-new' => $json],
            ],
        ];
    }
}
