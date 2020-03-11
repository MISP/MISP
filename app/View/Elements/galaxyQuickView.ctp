<?php
    $fixed_fields = array('synonyms', 'description', 'meta', 'authors', 'source');
    foreach ($data as $galaxy) {
        $cluster_data = '';
        foreach ($galaxy['GalaxyCluster'] as $cluster) {
            $cluster_fields = array();
            if (isset($cluster['description'])) {
                $cluster_fields[] = array('key' => 'description', 'value' => $cluster['description']);
            }
            if (isset($cluster['meta']['synonyms'])) {
                $cluster_fields[] = array('key' => 'synonyms', 'value' => $cluster['meta']['synonyms']);
            }
            if (isset($cluster['source'])) {
                $cluster_fields[] = array('key' => 'source', 'value' => $cluster['source']);
            }
            if (isset($cluster['authors'])) {
                $cluster_fields[] = array('key' => 'authors', 'value' => $cluster['authors']);
            }
            if (!empty($cluster['meta'])) {
                foreach ($cluster['meta'] as $metaKey => $metaField) {
                    if ($metaKey != 'synonyms') {
                        $cluster_fields[] = array('key' => $metaKey, 'value' => $metaField);
                    }
                }
            }
            $data = '';
            foreach ($cluster_fields as $cluster_field) {
                $dataKey = h(ucfirst($cluster_field['key']));
                $dataValue = '';
                if (is_array($cluster_field['value'])) {
                    if ($cluster_field['key'] == 'refs') {
                        $value = array();
                        foreach ($cluster_field['value'] as $k => $v) {
                            $v_name = strlen($v) > 30 ? substr($v, 0, 30) . '...' : $v;
                            $value[$k] = sprintf('<a href="%s" title="%s">%s</a>', h($v), h($v), h($v_name));
                        }
                        $dataValue .= nl2br(implode("\n", $value));
                    } else if($cluster_field['key'] == 'country') {
                        $value = array();
                        foreach ($cluster_field['value'] as $k => $v) {
                            $value[] = '<div class="famfamfam-flag-' . strtolower(h($v)) . '" ></div>&nbsp;' . h($v);
                        }
                        $dataValue .= nl2br(implode("\n", $value));
                    } else {
                        $dataValue .= nl2br(h(implode("\n", $cluster_field['value'])));
                    }
                } else {
                     if ($cluster_field['key'] == 'source' && filter_var($cluster_field['value'], FILTER_VALIDATE_URL)) {
                         $dataValue .= '<a href="' . h($cluster_field['value']) . '">' . h($cluster_field['value']) . '</a>';;
                     } else {
                        $dataValue .= h($cluster_field['value']);
                     }
                }
                $data .= sprintf(
                    '<div class="blue galaxy_data">%s</div>',
                    sprintf(
                        '<div class="row-fluid cluster_%s">%s%s</div>',
                        h($cluster_field['key']),
                        sprintf('<div class="span3 info_container_key">%s</div>', $dataKey),
                        sprintf('<div class="span9 info_container_value">%s</div>', $dataValue)
                    )
                );
            }
            $cluster_data .= sprintf(
                '<div class="large-left-margin"><span class="bold blue expandContainer">%s %s %s %s %s %s</span></div>',
                '<span class="collapse-status-container useCursorPointer"><span class="collapse-status">+</span></span>',
                sprintf(
                    '<span><i class="fas fa-%s"></i> %s</span>',
                    $cluster['local'] ? 'user' : 'globe-americas',
                    h($cluster['value'])
                ),
                sprintf(
                    '<a href="%s/galaxy_clusters/view/%s" class="fa fa-search" title="%s" aria-label="%s"></a>&nbsp;',
                    $baseurl,
                    h($cluster['id']),
                    __('View details about this cluster'),
                    __('View cluster')
                ),
                sprintf(
                    '<a href="%s/events/index/searchtag:%s" class="fa fa-list" title="%s" aria-label="%s"></a>',
                    $baseurl,
                    h($cluster['tag_id']),
                    __('View all events containing this cluster.'),
                    __('View all events containing this cluster.')
                ),
                !$isSiteAdmin && (!$mayModify || !$isAclTagger) ? '' : sprintf(
                    '%s%s%s',
                    $this->Form->create(
                        false,
                        array(
                            'url' => $baseurl . '/galaxy_clusters/detach/' . ucfirst(h($target_id)) . '/' . h($target_type) . '/' . $cluster['tag_id'],
                            'style' => 'display: inline-block; margin: 0px;'
                        )
                    ),
                    sprintf(
                        '<it href="#" class="fa fa-trash useCursorPointer" role="button" tabindex="0" aria-label="%s" title="%s" onclick="popoverConfirm(this)"></it>',
                        __('detach'),
                        __('Are you sure you want to detach %s from this event?', h($cluster['value']))
                    ),
                    $this->Form->end()
                ),
                $data
            );
        }
        echo sprintf(
            '<div class="large-left-margin"><span title="%s" class="bold blue" style="%s">%s&nbsp;%s%s</span></div>',
            isset($galaxy['description']) ? h($galaxy['description']) : h($galaxy['name']),
            'font-size:14px;',
            h($galaxy['name']),
            sprintf(
                '<a href="%s/galaxies/view/%s" class="fa fa-search" title="%s" aria-label="%s"></a>',
                $baseurl,
                h($galaxy['id']),
                __('View details about this galaxy'),
                __('View galaxy')
            ),
            $cluster_data
        );
    }
    if ($isSiteAdmin || ($mayModify && $isAclTagger)) {
        echo sprintf(
            '<button class="%s" data-target-type="%s" data-target-id="%s" data-local="false" role="button" tabindex="0" aria-label="' . __('Add new cluster') . '" title="' . __('Add a tag') . '" style="%s">%s</button>',
            'useCursorPointer btn btn-inverse addGalaxy',
            h($target_type),
            h($target_id),
            'line-height:10px; padding: 2px; margin-right:5px;',
            '<i class="fas fa-globe-americas"></i> +'
        );
    }
    if (
        (!isset($local_tag_off) || !$local_tag_off) &&
        ($isSiteAdmin || ($isAclTagger && Configure::read('MISP.host_org_id') == $me['org_id']))
    ) {
        echo sprintf(
            '<button class="%s" data-target-type="%s" data-target-id="%s" data-local="true" role="button" tabindex="0" aria-label="' . __('Add new local cluster') . '" title="' . __('Add a local tag') . '" style="%s">%s</button>',
            'useCursorPointer btn btn-inverse addGalaxy',
            h($target_type),
            h($target_id),
            'line-height:10px; padding: 2px;',
            '<i class="fas fa-user"></i> +'
        );
    }
?>
<script type="text/javascript">
    $(document).ready(function () {
        $('.collapse-status-container').click(function() {
            $(this).parent().children('.galaxy_data').toggle();
            if ($(this).parent().children('.collapse-status-container').children('.collapse-status').html() == '+') {
                $(this).parent().children('.collapse-status-container').children('.collapse-status').html('-');
            } else {
                $(this).parent().children('.collapse-status-container').children('.collapse-status').html('+');
            }
        });
    });
</script>
