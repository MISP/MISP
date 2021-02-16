<div class="pagination">
    <ul>
    <?php
        $this->Paginator->options(array(
            'data-paginator' => '#ajaxContent',
        ));

        $paginator = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
        $paginator .= $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
        $paginator .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        echo $paginator;
    ?>
    </ul>
</div>
<table class="table table-striped table-hover table-condensed">
    <tr>
        <th><?php echo $this->Paginator->sort('object_relation', __('Object relation'));?></th>
        <th><?php echo $this->Paginator->sort('type');?></th>
        <th><?php echo $this->Paginator->sort('multiple', __('Multiple'));?></th>
        <th><?php echo $this->Paginator->sort('ui-priority', __('UI-priority'));?></th>
        <th><?php echo $this->Paginator->sort('description');?></th>
        <th><?php echo __('Categories');?></th>
        <th><?php echo __('Sane defaults');?></th>
        <th><?php echo __('List of valid Values');?></th>
        <th><?php echo __('Disable correlation');?></th>
    </tr>
<?php
  $listItems = array('category', 'sane_default', 'values_list');
    foreach ($list as $k => $item):
?>
        <tr>
            <td class="short bold"><?php echo h($item['ObjectTemplateElement']['object_relation']); ?></td>
            <td class="short"><?php echo h($item['ObjectTemplateElement']['type']); ?></td>
            <td class="short"><span class="fa fa-<?php echo $item['ObjectTemplateElement']['multiple'] ? 'check' : 'times'; ?>"></span></td>
            <td class="short"><?php echo h($item['ObjectTemplateElement']['ui-priority']); ?></td>
            <td><?php echo h($item['ObjectTemplateElement']['description']); ?></td>
      <?php
        foreach ($listItems as $listItem):
      ?>
          <td class="short">
      <?php
            if (!empty($item['ObjectTemplateElement'][$listItem])) {
              foreach ($item['ObjectTemplateElement'][$listItem] as $value) {
                echo h($value) . '<br>';
              }
            }
      ?>
          </td>
      <?php
        endforeach;
      ?>
            <td class="short"><span class="fa fa-<?php echo empty($item['ObjectTemplateElement']['disable_correlation']) ? 'times': 'check'; ?>"></td>
        </tr>
    <?php
        endforeach;
    ?>
</table>
<p>
<?php
    echo $this->Paginator->counter(array('format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')));
?>
</p>
<div class="pagination">
    <ul>
    <?= $paginator ?>
    </ul>
</div>

