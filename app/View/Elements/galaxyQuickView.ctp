	<?php
    $fixed_fields = array('synonyms', 'description', 'meta', 'authors', 'source');
    foreach ($data as $galaxy):
?>
        <div style="margin-left:10px;">
            <span title="<?php echo isset($galaxy['description']) ? h($galaxy['description']) : h($galaxy['name']);?>" class="bold blue" style="font-size:14px;">
                <?php echo h($galaxy['name']); ?>&nbsp;
                <a href="<?php echo $baseurl; ?>/galaxies/view/<?php echo h($galaxy['id']); ?>" class="icon-search" title="<?php echo __('View details about this galaxy');?>"></a>
            </span>
    <?php
        foreach ($galaxy['GalaxyCluster'] as $cluster):
    ?>
            <div style="margin-left:8px;">
                <span class="bold blue expandContainer">
					<span class="collapse-status-container useCursorPointer">
                    	<span class="collapse-status" style="font-size: 16px;">+</span>
					</span>
                    <span><?php echo h($cluster['value']); ?></span>
                    <a href="<?php echo $baseurl; ?>/galaxy_clusters/view/<?php echo h($cluster['id']); ?>" class="icon-search" title="<?php echo __('View details about this cluster');?>"></a>&nbsp;
                    <a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($cluster['tag_id']); ?>" class="icon-th-list" title="<?php echo __('View all events containing this cluster.');?>"></a>
                    <?php
                        if ($isSiteAdmin || ($mayModify && $isAclTagger)) {
                            echo $this->Form->postLink('',
                                $baseurl . '/galaxy_clusters/detach/' . ucfirst(h($target_id)) . '/' . h($target_type) . '/' . $cluster['tag_id'],
                                array('class' => 'icon-trash', 'title' => __('Delete'), 'div' => false),
                                __('Are you sure you want to detach %s from this event?', h($cluster['value']))
                            );
                        }
                    ?>
                    <div style="margin-left:15px;display:none;" class="blue galaxy_data">
                        <?php
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
                            $data = array();
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
                                $dataKey = sprintf('<div class="span3 info_container_key">%s</div>', $dataKey);
                                $dataValue = sprintf('<div class="span9 info_container_value">%s</div>', $dataValue);
                                echo sprintf('<div class="row-fluid cluster_%s">%s%s</div>', h($cluster_field['key']), $dataKey, $dataValue);
                            }
                        ?>
                    </div>
                </span>
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
        <span class="useCursorPointer btn btn-inverse addGalaxy" data-target-type="<?php echo h($target_type);?>" data-target-id="<?php echo h($target_id); ?>" role="button" tabindex="0" aria-label="Add new cluster" style="padding: 1px 5px !important;font-size: 12px !important;">Add</span>
<?php
    endif;
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
    $('.delete-cluster').click(function() {
        var tagName = $(this).data('tag-name');
        removeTag($id = false, $tag_id = false, $galaxy = false);
    });
});
</script>
