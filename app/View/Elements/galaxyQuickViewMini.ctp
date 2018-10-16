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
    ?>
            <div style="margin-left:8px;">
                <span class="bold blue expandable useCursorPointer" data-toggle="popover" data-content="<?php echo h($popover_data); ?>">
                    <?php echo h($cluster['value']); ?>
                </span>&nbsp;
                <a href="<?php echo $baseurl; ?>/galaxy_clusters/view/<?php echo h($cluster['id']); ?>" class="icon-search" title="<?php echo __('View details about this cluster');?>"></a>&nbsp;
                <a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($cluster['tag_id']); ?>" class="icon-th-list" title="<?php echo __('View all events containing this cluster.');?>"></a>
                <?php
                    if ($isSiteAdmin || ($mayModify && $isAclTagger)) {
                        echo $this->Form->postLink('',
                            $baseurl . '/galaxy_clusters/detach/' . ucfirst(h($target_id)) . '/' . h($target_type) . '/' . $cluster['tag_id'],
                            array('class' => 'icon-trash', 'title' => 'Delete'),
                            __('Are you sure you want to detach %s from this %s?', h($cluster['value']), h($target_type))
                        );
                    }
                ?>
            </div>
<?php
        endforeach;
?>
    </div>
<?php
    endforeach;
?>
<?php
    if ($isSiteAdmin || ($mayModify && $isAclTagger)):
?>
        <span class="btn btn-inverse noPrint addGalaxy" data-target-type="<?php echo h($target_type);?>" data-target-id="<?php echo h($target_id); ?>" role="button" tabindex="0" aria-label="<?php echo __('Add new cluster');?>" style="padding: 1px 5px !important;font-size: 12px !important;"><?php echo __('Add');?></span>
<?php
    endif;
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
    $('.delete-cluster').click(function() {
        var tagName = $(this).data('tag-name');
        removeTag($id = false, $tag_id = false, $galaxy = false);
    });
});
</script>
