<div class="taxonomies index">
    <h2><?php echo __('Taxonomies');?></h2>
    <div class="pagination">
        <ul>
        <?php
        $this->Paginator->options(array(
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
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <th><?php echo $this->Paginator->sort('id');?></th>
            <th><?php echo $this->Paginator->sort('namespace');?></th>
            <th><?php echo $this->Paginator->sort('description');?></th>
            <th><?php echo $this->Paginator->sort('version');?></th>
            <th><?php echo $this->Paginator->sort('enabled');?></th>
            <th><?php echo __('Active Tags');?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr><?php
foreach ($taxonomies as $item): ?>
    <tr>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/taxonomies/view/".h($item['Taxonomy']['id']);?>'"><?php echo h($item['Taxonomy']['id']); ?>&nbsp;</td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/taxonomies/view/".h($item['Taxonomy']['id']);?>'"><?php echo h($item['Taxonomy']['namespace']); ?>&nbsp;</td>
        <td ondblclick="document.location.href ='<?php echo $baseurl."/taxonomies/view/".h($item['Taxonomy']['id']);?>'"><?php echo h($item['Taxonomy']['description']); ?>&nbsp;</td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/taxonomies/view/".h($item['Taxonomy']['id']);?>'"><?php echo h($item['Taxonomy']['version']); ?>&nbsp;</td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/taxonomies/view/".h($item['Taxonomy']['id']);?>'"><?php echo $item['Taxonomy']['enabled'] ? '<span class="green">Yes</span>' : '<span class="red">No</span>'; ?>&nbsp;</td>
        <td class="shortish"><span><span class="bold"><?php echo h($item['current_count']);?></span> / <?php echo h($item['total_count']);?> <?php if ($item['current_count'] != $item['total_count'] && $isSiteAdmin && $item['Taxonomy']['enabled']) echo '(' . $this->Form->postLink(__('enable all'), array('action' => 'addTag', h($item['Taxonomy']['id'])), array('title' => __('Enable all tags')), (__('Are you sure you want to enable every tag associated to this taxonomy?'))) . ')'; ?></span></td>
        <td class="short action-links">
            <?php
                if ($isSiteAdmin) {
                    if ($item['Taxonomy']['enabled']) {
                        echo $this->Form->postLink('', array('action' => 'disable', h($item['Taxonomy']['id'])), array('class' => 'icon-minus', 'title' => __('Disable')), (__('Are you sure you want to disable this taxonomy library?')));
                    } else {
                        echo $this->Form->postLink('', array('action' => 'enable', h($item['Taxonomy']['id'])), array('class' => 'icon-plus', 'title' => __('Enable')), (__('Are you sure you want to enable this taxonomy library?')));
                    }
                }
            ?>
            <a href='<?php echo $baseurl."/taxonomies/view/". h($item['Taxonomy']['id']);?>' class = "icon-list-alt" title = "<?php echo __('View');?>"></a>
            <span class="icon-trash useCursorPointer" title="<?php echo __('Delete taxonomy');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete taxonomy');?>" onClick="deleteObject('taxonomies', 'delete', '<?php echo h($item['Taxonomy']['id']); ?>', '<?php echo h($item['Taxonomy']['id']); ?>');"></span>
        </td>
    </tr><?php
endforeach; ?>
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
<?php
    echo $this->element('side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'index'));
?>
