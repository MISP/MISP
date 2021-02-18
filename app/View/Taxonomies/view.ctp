<div class="taxonomy view">
    <h2><?= __('%s Taxonomy Library', h(strtoupper($taxonomy['namespace'])));?></h2>
    <div class="row-fluid"><div class="span8" style="margin:0">
<?php
$enabled = $taxonomy['enabled'] ? '<span class="green">'. __('Yes') . '</span>&nbsp;&nbsp;' : '<span class="red">' . __('No') . '</span>&nbsp;&nbsp;';
if ($isSiteAdmin) {
    if ($taxonomy['enabled']) {
        $enabled .= $this->Form->postLink(__('(disable)'), array('action' => 'disable', h($taxonomy['id'])), array('title' => __('Disable')), (__('Are you sure you want to disable this taxonomy library?')));
    } else {
        $enabled .= $this->Form->postLink(__('(enable)'), array('action' => 'enable', h($taxonomy['id'])), array('title' => __('Enable')), (__('Are you sure you want to enable this taxonomy library?')));
    }
}
$tableData = [
    ['key' => __('ID'), 'value' => $taxonomy['id']],
    ['key' => __('Namespace'), 'value' => $taxonomy['namespace']],
    ['key' => __('Description'), 'value' => $taxonomy['description']],
    ['key' => __('Version'), 'value' => $taxonomy['version']],
    ['key' => __('Enabled'), 'html' => $enabled],
];
echo $this->element('genericElements/viewMetaTable', ['table_data' => $tableData]);
?>
    </div></div>
    <br>
    <div class="pagination">
        <ul>
        <?php
        if (!empty($filter)) $url = array($id, 'filter:' . $filter);
        else $url = array($id);
        $this->Paginator->options(array(
            'url' => $url,
        ));

            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
     <div id="attributeList" class="attributeListContainer">
        <div class="tabMenuFixedContainer">
            <div class="tabMenu tabMenuEditBlock noPrint mass-select" style="float:left;top:-1px;">
                <span id="multi-edit-button" title="Create / update selected tags" role="button" tabindex="0" aria-label="<?php echo __('Create and/or update selected tags');?>" class="icon-plus useCursorPointer" onClick="addSelectedTaxonomies(<?php echo $taxonomy['id']; ?>);"></span>
            </div>
            <div style="float:right !important;overflow:hidden;border:0px;padding:0px;padding-right:200px;">
                    <input type="text" id="quickFilterField" class="tabMenuFilterField taxFilter" value="<?php echo h($filter);?>" /><span id="quickFilterButton" class="useCursorPointer taxFilterButton" onClick='quickFilterTaxonomy("<?php echo h($taxonomy['id']);?>");'><?php echo __('Filter');?></span>
            </div>
            <span class="tabMenuFixed tabMenuFixedLeft tabMenuSides useCursorPointer  noPrint mass-select" style="margin-left:50px;">
                <span id="multi-edit-button" title="<?php echo __('Hide selected tags');?>" role="button" tabindex="1" aria-label="<?php echo __('Hide selected tags');?>" class="useCursorPointer" onClick="hideSelectedTags(<?php echo $taxonomy['id']; ?>);">
                    <?php echo __('Hide selected tags');?>
                </span>
            </span>
            <span class="tabMenuFixed tabMenuFixedLeft tabMenuSides useCursorPointer  noPrint mass-select">
                <span id="multi-edit-button" title="<?php echo __('Unhide selected tags');?>" role="button" tabindex="2" aria-label="<?php echo __('Unhide selected tags');?>" class="useCursorPointer" onClick="unhideSelectedTags(<?php echo $taxonomy['id']; ?>);">
                    <?php echo __('Unhide selected tags');?>
                </span>
            </span>
        </div>
        <table class="table table-striped table-hover table-condensed">
            <tr>
                <?php if ($isAclTagger && !empty($entries)): ?>
                    <th><input class="select_all" type="checkbox" onClick="toggleAllTaxonomyCheckboxes();" /></th>
                <?php endif;?>
                    <th><?php echo $this->Paginator->sort('tag', __('Tag'));?></th>
                    <th><?php echo $this->Paginator->sort('expanded', __('Expanded'));?></th>
                    <th><?php echo $this->Paginator->sort('numerical_value', __('Numerical value'));?></th>
                    <th><?php echo $this->Paginator->sort('events');?></th>
                    <th><?php echo $this->Paginator->sort('attributes');?></th>
                    <th><?php echo $this->Paginator->sort('tag', __('Tags'));?></th>
                    <th><?php echo __('Action');?></th>
            </tr><?php
            foreach ($entries as $k => $item): ?>
            <tr>
            <?php if ($isAclTagger): ?>
                <td style="width:10px;">
                    <input id = "select_<?php echo h($k); ?>" class="select_taxonomy" type="checkbox" data-id="<?php echo h($k);?>" />
                </td>
            <?php endif; ?>
                <td id="tag_<?php echo h($k); ?>" class="short"><?php echo h($item['tag']); ?></td>
                <td><?php echo h($item['expanded']); ?></td>
                <td class="short">
                    <?php echo isset($item['numerical_value']) ? h($item['numerical_value']) : ''; ?>&nbsp;
                    <?php if(isset($item['original_numerical_value'])): ?>
                        <i
                            class="<?= $this->FontAwesome->getClass('exclamation-triangle') ?>"
                            title="<?= __('Numerical value overridden by userSetting.&#10;Original numerical_value = %s', h($item['original_numerical_value'])) ?>"
                            data-value-overriden="1"
                        ></i>
                    <?php endif; ?>
                </td>
                <td class="short">
                <?php
                    if ($item['existing_tag']) {
                ?>
                    <a href="<?= $baseurl."/events/index/searchtag:". h($item['existing_tag']['Tag']['id']);?>"><?php echo h($item['events']);?></a>
                <?php
                    } else {
                        echo __('N/A');
                    }
                ?>
                </td>
                <td class="short">
                <?php
                    if ($item['existing_tag']):
                ?>
                        <a href="<?= $baseurl."/attributes/search/tags:". h($item['existing_tag']['Tag']['id']);?>"><?php echo h($item['attributes']);?></a>
                <?php
                    else:
                        echo __('N/A');
                    endif;
                ?>
                </td>
                <td class="short">
                <?php
                    if ($item['existing_tag']):
                        if ($item['existing_tag']['Tag']['hide_tag']):
                ?>
                            <span class="red bold"><?php echo __('Hidden');?></span>
                <?php
                        else:
                            $url = $baseurl . '/events/index/searchtag:' .  h($item['existing_tag']['Tag']['id']);
                            if ($isAclTagger) $url = $baseurl . '/tags/edit/' .  h($item['existing_tag']['Tag']['id']);
                ?>
                        <a href="<?php echo $url;?>" data-tag-id="<?= h($item['existing_tag']['Tag']['id']) ?>" class="<?php echo $isAclTagger ? 'tag tagFirstHalf' : 'tag' ?>" style="background-color:<?php echo h($item['existing_tag']['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($item['existing_tag']['Tag']['colour']);?>"><?php echo h($item['existing_tag']['Tag']['name']); ?></a>
                <?php
                        endif;
                        echo '&nbsp;' . $this->Html->link('', array('controller' => 'tags', 'action' => 'viewGraph', $item['existing_tag']['Tag']['id']), array('class' => 'fa fa-share-alt black', 'title' => __('View correlation graph'), 'aria-label' => __('View correlation graph')));
                    endif;
                ?>
                </td>
                <td class="action">
                    <?php
                        if ($isAclTagger && $taxonomy['enabled']) {
                            echo $this->Form->create('Tag', array('id' => 'quick_' . h($k), 'url' => $baseurl . '/taxonomies/addTag/', 'style' => 'margin:0px;'));
                            echo $this->Form->input('name', array('type' => 'hidden', 'value' => $item['tag']));
                            echo $this->Form->input('taxonomy_id', array('type' => 'hidden', 'value' => $taxonomy['id']));
                            echo $this->Form->end();
                            if ($item['existing_tag'] && !$item['existing_tag']['Tag']['hide_tag']):
                                echo $this->Form->create('Tag', array('id' => 'quick_disable_' . h($k), 'url' => $baseurl . '/taxonomies/disableTag/', 'style' => 'margin:0px;'));
                                echo $this->Form->input('name', array('type' => 'hidden', 'value' => $item['tag']));
                                echo $this->Form->input('taxonomy_id', array('type' => 'hidden', 'value' => $taxonomy['id']));
                                echo $this->Form->end();
                        ?>
                                <span class="fa fa-sync useCursorPointer" title="<?php echo __('Refresh');?>" role="button" tabindex="0" aria-label="<?php echo __('Refresh');?>" onClick="submitQuickTag('<?php echo 'quick_' . h($k); ?>');"></span>
                                <span class="icon-minus useCursorPointer" title="<?php echo __('Disable');?>" role="button" tabindex="0" aria-label="<?php echo __('Disable');?>" onClick="submitQuickTag('<?php echo 'quick_disable_' . h($k); ?>');"></span>
                        <?php
                            else:
                        ?>
                                <span class="icon-plus useCursorPointer" title="<?php echo __('Enable');?>" role="button" tabindex="0" aria-label="<?php echo __('Refresh or enable');?>" onClick="submitQuickTag('<?php echo 'quick_' . h($k); ?>');"></span>
                        <?php
                            endif;
                            echo $this->Form->end();
                        } else {
                            echo __('N/A');
                        }
                    ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
        <p>
        <?php
        echo $this->Paginator->counter(array(
        'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
        ));
        ?>
        </p>
        <div class="pagination">
            <ul>
            <?php
                echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
                echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
                echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            ?>
            </ul>
        </div>
    </div>
</div>
<script type="text/javascript">
    $(function(){
        $('input:checkbox').removeAttr('checked');
        $('.mass-select').hide();
        $('.select_taxonomy, .select_all').click(function(){
            taxonomyListAnyCheckBoxesChecked();
        });
        $('[data-value-overriden="1"]').tooltip();
    });
</script>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'view'));
