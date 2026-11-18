<?php
App::uses('AppHelper', 'View/Helper');

/**
 * The columns of a value's occurrence table, shared by the Overview's
 * Occurrences card and the Occurrences tab so the two draw one table.
 *
 * The global attribute index's columns (`Elements/Attributes/index`), less
 * what a value page has no use for: the value (the same on every row;
 * Context says when a row spells it otherwise), and Related, Feeds,
 * Sightings and Analyst data, which the page answers in their own tabs.
 * Each row leads with its event's id and icon, then the organisation that
 * reported it.
 */
class ValueOccurrenceHelper extends AppHelper
{
    /**
     * @param array $options
     *   plan      the reader's label plan, which picks the chip a Tags or
     *             Galaxy cell draws first
     *   select    a selection column, for the tab's mass actions
     *   sortable  sort links on Event, Category, Type and Last seen
     *   feeds     a Feeds column (Fields/feedHits), as on the global index
     *   seen      a Last seen column
     * @return array index_table fields
     */
    public function fields(array $options = array())
    {
        $view = $this->_View;
        $baseurl = $view->viewVars['baseurl'] ?? '';
        $plan = $options['plan'] ?? null;
        $sortable = !empty($options['sortable']);
        $canGraph = $view->Acl->canAccess('workspaces', 'addNodes');
        $canCollect = $view->Acl->canAccess('collectionElements', 'addElementToCollection');
        $sort = function ($column) use ($sortable) {
            return $sortable ? array('sort' => $column) : array();
        };

        $fields = array();
        if (!empty($options['select'])) {
            $fields[] = array(
                'element' => 'checkbox',
                'data_path' => 'Attribute.id',
                'graph_item' => function ($row) {
                    if (!empty($row['Attribute']['deleted'])) {
                        return null;
                    }
                    return array(
                        'type' => 'Attribute',
                        'uuid' => $row['Attribute']['uuid'],
                        'label' => $row['Attribute']['value'],
                    );
                },
            );
        }
        $fields[] = array(
            'name' => __('Event'),
            'element' => 'custom',
            'class' => 'vp-occ-event',
            'function' => function ($row) use ($view) {
                $event = $row['Event'] ?? array();
                if (empty($event['id'])) {
                    return '';
                }
                return $view->element('Attributes/event_ref', array('event' => $event));
            },
        ) + $sort('Attribute.event_id');
        $fields[] = array(
            'name' => __('Reported by'),
            'element' => 'custom',
            // As the Reporting card's Reported by column.
            'function' => function ($row) use ($view) {
                return empty($row['Event']['Orgc'])
                    ? ''
                    : $view->element('Values/View/value_org_link', array(
                        'org' => $row['Event']['Orgc'],
                    ));
            },
        );
        $fields[] = array(
            'name' => __('Context'),
            'element' => 'value_object_context',
            'object_name_path' => 'Object.name',
            'object_id_path' => 'Object.id',
            'relation_path' => 'Attribute.object_relation',
            'comment_path' => 'Attribute.comment',
            'spelled_path' => 'spelled',
        );
        $fields[] = array(
            'name' => __('Category'),
            'data_path' => 'Attribute.category',
            'element' => 'category',
        ) + $sort('Attribute.category');
        $fields[] = array(
            'name' => __('Type'),
            'data_path' => 'Attribute.type',
            'element' => 'type',
        ) + $sort('Attribute.type');
        // The tags and clusters of both the attribute and its event: on a
        // value the event's labels are most of what there is.
        $fields[] = array(
            'name' => __('Tags'),
            'element' => 'value_tag_list',
            'data_path' => 'AttributeTag',
            'event_data_path' => 'EventTag',
            'max_visible' => 1,
            'plan' => $plan,
        );
        $fields[] = array(
            'name' => __('Galaxy'),
            'element' => 'value_cluster_list',
            'data_path' => 'Cluster',
            'max_visible' => 1,
            'plan' => $plan,
        );
        if (!empty($options['feeds'])) {
            $fields[] = array(
                'name' => __('Feed hits'),
                'header_html' => h(__('Feeds')),
                'header_title' => __('Feed hits'),
                'element' => 'feedHits',
            );
        }
        if (!empty($options['seen'])) {
            $fields[] = array(
                'name' => __('Last seen'),
                'element' => 'datetime',
                'data_path' => 'Attribute.last_seen',
                'format' => 'Y-m-d H:i',
                // "Not set" rather than a dash: an optional value, not a missing one.
                'empty' => __('Not set'),
            ) + $sort('Attribute.last_seen');
        }
        $fields[] = array(
            'name' => __('IDS'),
            'header_html' => '<i class="fas fa-shield-halved"></i>',
            'header_title' => __('IDS'),
            'header_class' => 'text-center',
            'class' => 'text-center',
            'data_path' => 'Attribute.to_ids',
            'element' => 'ids',
            // This page reports the flag; the event that owns it sets it.
            'readonly' => true,
        );
        $fields[] = array(
            'name' => __('Correlate'),
            'header_html' => '<i class="fas fa-link"></i>',
            'header_title' => __('Correlate'),
            'header_class' => 'text-center',
            'class' => 'text-center',
            'data_path' => 'Attribute.disable_correlation',
            'element' => 'correlate',
            'readonly' => true,
        );
        $fields[] = array(
            'name' => __('Actions'),
            'header_html' => '',
            'header_title' => __('Actions'),
            'element' => 'row_actions',
            'data_path' => 'Attribute.id',
            'actions' => array(
                array(
                    'type' => 'copy',
                    'label' => __('Copy UUID'),
                    'icon' => 'copy',
                    'data_path' => 'Attribute.uuid',
                    'copy_message' => __('UUID copied to clipboard'),
                ),
                array(
                    'type' => 'navigate',
                    'label' => __('View the event'),
                    'icon' => 'misp-icon misp-icon-event misp-simple',
                    'url' => $baseurl . '/events/view/%event_id%',
                    'url_params_data_paths' => array('event_id' => 'Attribute.event_id'),
                ),
                array(
                    'type' => 'divider',
                    'requirement' => function ($row) use ($canGraph, $canCollect) {
                        return ($canGraph || $canCollect) && empty($row['Attribute']['deleted']);
                    },
                ),
                array(
                    'type' => 'modal',
                    'label' => __('Add to collection'),
                    'icon' => 'folder-plus',
                    'url' => $baseurl . '/collectionElements/addElementToCollection/Attribute/%uuid%',
                    'url_params_data_paths' => array('uuid' => 'Attribute.uuid'),
                    'size' => 'xl',
                    'requirement' => function ($row) use ($canCollect) {
                        return $canCollect && empty($row['Attribute']['deleted']);
                    },
                ),
                array(
                    'type' => 'intelGraph',
                    'label' => __('Add to workspace'),
                    'icon' => 'text-analystGraph misp-icon misp-icon-analyst-graph misp-simple',
                    'items' => function ($row) {
                        return array(array(
                            'type' => 'Attribute',
                            'uuid' => $row['Attribute']['uuid'],
                            'label' => $row['Attribute']['value'],
                        ));
                    },
                    'requirement' => function ($row) use ($canGraph) {
                        return $canGraph && empty($row['Attribute']['deleted']);
                    },
                ),
            ),
        );
        return $fields;
    }
}
