<div class="taxonomy view">
<h2><?php echo h(strtoupper($taxonomy['namespace'])) . ' ' . __('Taxonomy Library');?></h2>
    <dl>
        <dt><?php echo __('Id');?></dt>
        <dd>
            <?php echo h($taxonomy['id']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Namespace');?></dt>
        <dd>
            <?php echo h($taxonomy['namespace']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Description');?></dt>
        <dd>
            <?php echo h($taxonomy['description']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Version');?></dt>
        <dd>
            <?php echo h($taxonomy['version']); ?>
            &nbsp;
        </dd>
        <dt><?php echo __('Enabled');?></dt>
        <dd>
            <?php echo $taxonomy['enabled'] ? '<span class="green">'. __('Yes') . '</span>&nbsp;&nbsp;' : '<span class="red">' . __('No') . '</span>&nbsp;&nbsp;';
                if ($isSiteAdmin) {
                    if ($taxonomy['enabled']) {
                        echo $this->Form->postLink('(disable)', array('action' => 'disable', h($taxonomy['id'])), array('title' => __('Disable')), (__('Are you sure you want to disable this taxonomy library?')));
                    } else {
                        echo $this->Form->postLink('(enable)', array('action' => 'enable', h($taxonomy['id'])), array('title' => __('Enable')), (__('Are you sure you want to enable this taxonomy library?')));
                    }
                }
            ?>

            &nbsp;
        </dd>
    </dl>
    <br />
    <div class="pagination">
        <ul>
        <?php
        if (!empty($filter)) $url = array($id, 'filter:' . $filter);
        else $url = array($id);
        $this->Paginator->options(array(
            'url' => $url,
            'update' => '.span12',
            'evalScripts' => true,
            'before' => '$(".progress").show()',
            'complete' => '$(".progress").hide()',
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
        </div>
        <table class="table table-striped table-hover table-condensed">
            <tr>
                <?php if ($isAclTagger && !empty($entries)): ?>
                    <th><input class="select_all" type="checkbox" onClick="toggleAllTaxonomyCheckboxes();" /></th>
                <?php endif;?>
                    <th><?php echo $this->Paginator->sort('tag');?></th>
                    <th><?php echo $this->Paginator->sort('expanded');?></th>
					<th><?php echo $this->Paginator->sort('numerical_value');?></th>
                    <th><?php echo $this->Paginator->sort('events');?></th>
                    <th><?php echo $this->Paginator->sort('attributes');?></th>
                    <th><?php echo $this->Paginator->sort('tag');?></th>
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
                <td><?php echo h($item['expanded']); ?>&nbsp;</td>
				<td class="short"><?php echo isset($item['numerical_value']) ? h($item['numerical_value']) : ''; ?>&nbsp;</td>
                <td class="short">
                <?php
                    if ($item['existing_tag']) {
                ?>
                    <a href='<?php echo $baseurl."/events/index/searchtag:". h($item['existing_tag']['Tag']['id']);?>'><?php echo count($item['existing_tag']['EventTag']);?></a>
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
                        <a href='<?php echo $baseurl."/attributes/search/attributetag:". h($item['existing_tag']['Tag']['id']);?>'><?php echo count($item['existing_tag']['AttributeTag']);?></a>
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
                        <a href="<?php echo $url;?>" class="<?php echo $isAclTagger ? 'tagFirstHalf' : 'tag' ?>" style="background-color:<?php echo h($item['existing_tag']['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($item['existing_tag']['Tag']['colour']);?>"><?php echo h($item['existing_tag']['Tag']['name']); ?></a>
                <?php
                        endif;
                        echo '&nbsp;' . $this->Html->link('', array('controller' => 'tags', 'action' => 'viewGraph', $item['existing_tag']['Tag']['id']), array('class' => 'fa fa-share-alt black', 'title' => __('View graph')));
                    endif;
                ?>
                </td>
                <td class="action">
                    <?php
                        if ($isAclTagger && $taxonomy['enabled']) {
                            echo $this->Form->create('Tag', array('id' => 'quick_' . h($k), 'url' => '/taxonomies/addTag/', 'style' => 'margin:0px;'));
                            echo $this->Form->input('name', array('type' => 'hidden', 'value' => $item['tag']));
                            echo $this->Form->input('taxonomy_id', array('type' => 'hidden', 'value' => $taxonomy['id']));
                            echo $this->Form->end();
                            if ($item['existing_tag'] && !$item['existing_tag']['Tag']['hide_tag']):
                                echo $this->Form->create('Tag', array('id' => 'quick_disable_' . h($k), 'url' => '/taxonomies/disableTag/', 'style' => 'margin:0px;'));
                                echo $this->Form->input('name', array('type' => 'hidden', 'value' => $item['tag']));
                                echo $this->Form->input('taxonomy_id', array('type' => 'hidden', 'value' => $taxonomy['id']));
                                echo $this->Form->end();
                        ?>
                                <span class="icon-refresh useCursorPointer" title="<?php echo __('Refresh');?>" role="button" tabindex="0" aria-label="<?php echo __('Refresh');?>" onClick="submitQuickTag('<?php echo 'quick_' . h($k); ?>');"></span>
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
    $(document).ready(function(){
        $('input:checkbox').removeAttr('checked');
        $('.mass-select').hide();
        $('.select_taxonomy, .select_all').click(function(){
            taxonomyListAnyCheckBoxesChecked();
        });
    });
</script>
<?php
    echo $this->element('side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'view'));
?>
