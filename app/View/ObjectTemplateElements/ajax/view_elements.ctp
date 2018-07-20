<div class="pagination">
    <ul>
    <?php
        $this->Paginator->options(array(
                'update' => '#clusters_div',
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
        <th><?php echo $this->Paginator->sort('object_relation');?></th>
        <th><?php echo $this->Paginator->sort('type');?></th>
        <th><?php echo $this->Paginator->sort('multiple');?></th>
    <th><?php echo $this->Paginator->sort('ui-priority', 'UI-priority');?></th>
    <th><?php echo $this->Paginator->sort('description');?></th>
    <th><?php echo __('Categories');?></th>
        <th><?php echo __('Sane defaults');?></th>
        <th><?php echo __('List of valid Values');?></th>
        <th><?php echo __('Disable correlation');?></th>
        <th class="actions"><?php echo __('Actions');?></th>
    </tr>
<?php
  $listItems = array('category', 'sane_default', 'values_list');
    foreach ($list as $k => $item):
?>
        <tr>
            <td class="short bold"><?php echo h($item['ObjectTemplateElement']['object_relation']); ?>&nbsp;</td>
      <td class="short"><?php echo h($item['ObjectTemplateElement']['type']); ?>&nbsp;</td>
            <td class="short"><span class="icon-<?php echo $item['ObjectTemplateElement']['multiple'] ? 'ok' : 'remove'; ?>"></span></td>
      <td class="short"><?php echo h($item['ObjectTemplateElement']['ui-priority']); ?>&nbsp;</td>
      <td><?php echo h($item['ObjectTemplateElement']['description']); ?>&nbsp;</td>
      <?php
        foreach ($listItems as $listItem):
      ?>
          <td class="short">
      <?php
            if (!empty($item['ObjectTemplateElement'][$listItem])) {
              foreach ($item['ObjectTemplateElement'][$listItem] as $value) {
                echo h($value) . '</br>';
              }
            }
      ?>
          </td>
      <?php
        endforeach;
      ?>
            <td class="short"><span class="icon-<?php echo empty($item['ObjectTemplateElement']['disable_correlation']) ? 'remove': 'ok'; ?>">&nbsp;</td>
            <td class="short action-links">
                &nbsp;
            </td>
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
    <?php
        echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
        echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
        echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
    ?>
    </ul>
</div>

<script type="text/javascript">
    $(document).ready(function(){
    });
</script>
<?php echo $this->Js->writeBuffer(); ?>
