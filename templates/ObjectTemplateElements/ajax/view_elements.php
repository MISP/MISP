<div class="pagination">
    <ul>
    <?php
        $this->Paginator->options(array(
            'data-paginator' => '#ajaxContent',
        ));
        $paginator = sprintf(
            '<nav aria-label="%s"><div class="pagination"><ul class="pagination">%s%s%s</ul></div></nav>',
            __(''),
            $this->Paginator->prev(__('Previous')),
            $this->Paginator->numbers(['first' => 1, 'last' => 1]),
            $this->Paginator->next(__('Next'))
        );

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
            <td class="short bold"><?php echo h($item['object_relation']); ?></td>
            <td class="short"><?php echo h($item['type']); ?></td>
            <td class="short"><span class="fa fa-<?php echo $item['multiple'] ? 'check' : 'times'; ?>"></span></td>
            <td class="short"><?php echo h($item['ui-priority']); ?></td>
            <td><?php echo h($item['description']); ?></td>
      <?php
        foreach ($listItems as $listItem):
      ?>
          <td class="short">
      <?php
            if (!empty($item[$listItem])) {
              foreach ($item[$listItem] as $value) {
                echo h($value) . '<br>';
              }
            }
      ?>
          </td>
      <?php
        endforeach;
      ?>
            <td class="short"><span class="fa fa-<?php echo empty($item['disable_correlation']) ? 'times': 'check'; ?>"></td>
        </tr>
    <?php
        endforeach;
    ?>
</table>
<p>
<?php
    echo $this->Paginator->counter('Page {{page}} of {{pages}}, showing {{current}} records out of {{count}} total, starting on record {{start}}, ending on {{end}}');
?>
</p>
<div class="pagination">
    <ul>
    <?= $paginator ?>
    </ul>
</div>

