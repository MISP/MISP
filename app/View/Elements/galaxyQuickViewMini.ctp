<?php
    $fixed_fields = array('synonyms', 'description', 'meta', 'authors', 'source');
    foreach ($data as $galaxy):
?>
        <div>
            <span title="<?php echo isset($galaxy['description']) ? h($galaxy['description']) : h($galaxy['name']);?>" class="bold blue" style="font-size:14px;">
                <?php echo h($galaxy['name']); ?>&nbsp;
            </span>
    <?php
        foreach ($galaxy['GalaxyCluster'] as $cluster):
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
            $popover_data = sprintf('<h4 class="blue bold">%s</h4>', h($cluster['value']));
            foreach ($cluster_fields as $cluster_field) {
                $key = sprintf('<span class="blue bold">%s</span>', Inflector::humanize(h($cluster_field['key'])));
                if (is_array($cluster_field['value'])) {
                    if ($cluster_field['key'] == 'refs') {
                        $value = array();
                        foreach ($cluster_field['value'] as $k => $v) {
                            $v_name = $v;
                            if (strlen($v_name) > 30) {
                                $v_name = substr($v, 0, 30) . '...';
                            }
                            $value[$k] = '<a href="' . h($v) . '" title="' . h($v) . '">' . h($v_name) . '</a>';
                        }
                        $value_contents = nl2br(implode("\n", $value));
                    } else if($cluster_field['key'] == 'country') {
                        $value = array();
                        foreach ($cluster_field['value'] as $k => $v) {
                            $value[] = '<span class="famfamfam-flag-' . strtolower(h($v)) . '" ></span>&nbsp;' . h($v);
                        }
                        $value_contents = nl2br(implode("\n", $value));
                    } else {
                        $value_contents = nl2br(h(implode("\n", $cluster_field['value'])));
                    }
                } else {
                     if ($cluster_field['key'] == 'source' && filter_var($cluster_field['value'], FILTER_VALIDATE_URL)) {
                         $value_contents = '<a href="' . h($cluster_field['value']) . '">' . h($cluster_field['value']) . '</a>';;
                     } else {
                        $value_contents = h($cluster_field['value']);
                     }
                }
                $value = sprintf('<span class="black">%s</span>', $value_contents);
                $popover_data .= sprintf('<span>%s: %s</span><br />', $key, $value);
            }
            echo sprintf(
                '<div class="large-left-margin">%s %s %s %s</div>',
                sprintf(
                    '<span class="bold blue expandable useCursorPointer" data-toggle="popover" data-content="%s">%s</span>',
                    h($popover_data),
                    sprintf(
                        '<span><i class="fas fa-%s"></i> %s</span>',
                        $cluster['local'] ? 'user' : 'globe-americas',
                        h($cluster['value'])
                    )
                ),
                sprintf(
                    '<a href="%s/galaxy_clusters/view/%s" class="black fas fa-search" title="%s" aria-label="%s"></a>',
                    $baseurl,
                    h($cluster['id']),
                    __('View details about this cluster'),
                    __('View cluster')
                ),
                sprintf(
                    '<a href="%s/events/index/searchtag:%s" class="black fas fa-list" title="%s" aria-label="%s"></a>',
                    $baseurl,
                    h($cluster['tag_id']),
                    __('View all events containing this cluster.'),
                    __('View all events containing this cluster.')
                ),
                (!empty($static_tags_only) || (!$isSiteAdmin && (!$mayModify || !$isAclTagger))) ? '' : sprintf(
                    '%s%s%s',
                    $this->Form->create(
                        false,
                        array(
                            'url' => $baseurl . '/galaxy_clusters/detach/' . ucfirst(h($target_id)) . '/' . h($target_type) . '/' . h($cluster['tag_id']),
                            'style' => 'display: inline-block; margin: 0px;'
                        )
                    ),
                    sprintf(
                        '<span href="#" class="fa fa-trash useCursorPointer" title="%s" onclick="popoverConfirm(this)"></span>',
                        __('Are you sure you want to detach %s from this %s?', h($cluster['value']), h($target_type))
                    ),
                    $this->Form->end()
                )
            );
        endforeach;
?>
    </div>
<?php
    endforeach;
?>
<?php
    if (empty($static_tags_only)) {
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
    }
?>

<script type="text/javascript">
$(document).ready(function () {
    $('.expandable').click(function() {
        $(this).parent().children('div').toggle();
        if ($(this).children('span').html() == '+') {
            $(this).children('span').html('-');
        } else {
            $(this).children('span').html('+');
        }
    });
});
</script>
