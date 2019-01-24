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
<?php
    $tab = "Center";
    $filtered = false;
    if(isset($passedArgsArray)){
        if (count($passedArgsArray) > 0) {
            $tab = "Left";
            $filtered = true;
        }
    }
?>
<div class="tabMenuFixedContainer" style="display:inline-block;">
    <?php if ($filtered):
        foreach ($passedArgsArray as $k => $v):?>
            <span class="tabMenuFixed tabMenuFixedElement">
                <?php echo h(ucfirst($k)) . " : " . h($v); ?>
            </span>
        <?php endforeach; ?>
        <span class="tabMenuFixed tabMenuFixedRight tabMenuSides">
            <?php echo $this->Html->link('', array('controller' => 'galaxies', 'action' => 'view/'. $galaxy_id), array('class' => 'icon-remove', 'title' => 'Remove filters'));?>
        </span>
    <?php endif;?>
    <span style="border-right:0px !important;">
        <span id="quickFilterButton" role="button" tabindex="0" aria-label="Filter value galaxie cluster" class="tabMenuFilterFieldButton useCursorPointer"
            onClick="quickFilter('', '<?php echo $baseurl . '/galaxies/view/' . $galaxy_id; ?>');">Filter</span>
        <input class="tabMenuFilterField" type="text" id="quickFilterField"></input>
    </span>
</div>
<table class="table table-striped table-hover table-condensed">
    <tr>
        <th><?php echo $this->Paginator->sort('value');?></th>
        <th><?php echo $this->Paginator->sort('synonyms');?></th>
        <th>Activity</th>
        <th>#Events</th>
        <th><?php echo $this->Paginator->sort('description');?></th>
        <th class="actions"><?php echo __('Actions');?></th>
    </tr>
<?php
    foreach ($list as $k => $item):
?>
        <tr>
            <td class="short bold"><?php echo h($item['GalaxyCluster']['value']); ?>&nbsp;</td>
            <td class="short bold">
                <?php
                    echo nl2br(h(implode("\n", $item['GalaxyCluster']['synonyms'])));
                ?>
                &nbsp;
            </td>
            <td class="shortish">
                <?php echo $this->element('sparkline', array('id' => $item['GalaxyCluster']['id'], 'csv' => $csv[$k])); ?>
            </td>
            <td class="short">
                <?php
                    if (!empty($item['GalaxyCluster']['event_count'])):
                ?>
                    <a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($item['GalaxyCluster']['tag_id']);?>" class="bold"><?php echo h($item['GalaxyCluster']['event_count']);?></a>
                <?php
                    else:
                        echo '0';
                    endif;
                ?>
            </td>
            <td><?php echo h($item['GalaxyCluster']['description']); ?>&nbsp;</td>
            <td class="short action-links">
                <?php echo $this->Html->link('', array('controller' => 'galaxies', 'action' => 'viewGraph', $item['GalaxyCluster']['id']), array('class' => 'fa fa-share-alt', 'title' => 'View graph'));?>
                <?php echo $this->Html->link('', array('action' => 'view', $item['GalaxyCluster']['id']), array('class' => 'icon-list-alt', 'title' => 'View'));?>
				<span class="icon-trash useCursorPointer" title="<?php echo __('Delete galaxy cluster');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete galaxy cluster');?>" onClick="deleteObject('galaxy_clusters', 'delete', '<?php echo h($item['GalaxyCluster']['id']); ?>', '<?php echo h($item['GalaxyCluster']['id']); ?>');"></span>
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
