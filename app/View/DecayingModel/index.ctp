<div class="templates index">
    <h2><?php echo __('Decaying Models');?></h2>
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
            <th><?php echo $this->Paginator->sort('org');?></th>
            <th><?php echo $this->Paginator->sort('all_orgs');?></th>
            <th><?php echo $this->Paginator->sort('name');?></th>
            <th><?php echo $this->Paginator->sort('description');?></th>
            <th>
                <?php echo __('Parameters'); ?>
                <a class="useCursorPointer" title="<?php echo __('Pretty print') ?>"><b style="font-size: larger;" onclick="prettyPrintJson();">{ }</b></a>

            </th>
            <th><?php echo $this->Paginator->sort('formula');?></th>
            <th><?php echo __('# Assigned Types') ?></th>
            <th><?php echo $this->Paginator->sort('version');?></th>
            <th><?php echo $this->Paginator->sort('enabled');?></th>
            <?php if ($isAclTemplate): ?>
                <th class="actions"><?php echo __('Actions');?></th>
            <?php endif; ?>
    </tr><?php
foreach ($decayingModel as $item): ?>
    <tr>
        <td class="short"><a href="<?php echo $baseurl."/decayingModel/view/".$item['DecayingModel']['id']; ?>"><?php echo h($item['DecayingModel']['id']); ?>&nbsp;</a></td>
        <td class="short">
            <?php
                echo $this->OrgImg->getOrgImg(array('name' => $item['DecayingModel']['org_id'], 'size' => 24));
            ?>
            &nbsp;
        </td>
        <td><i class="fas fa-<?php echo $item['DecayingModel']['all_orgs'] ? 'check' : 'times';?>"></i></td>
        <td>
            <a href="<?php echo $baseurl."/decayingModel/view/".$item['DecayingModel']['id']; ?>"><?php echo h($item['DecayingModel']['name']); ?>&nbsp;</a>
            <?php if ($item['DecayingModel']['isDefault']): ?>
                <img src="<?php echo $baseurl;?>/img/orgs/MISP.png" width="24" height="24" style="padding-bottom:3px;" title="<?php echo __('Default Model from MISP Project'); ?>" />
            <?php endif; ?>
        </td>
        <td><?php echo h($item['DecayingModel']['description']); ?>&nbsp;</td>
        <?php
            if (isset($item['DecayingModel']['parameters']['base_score_config']) && empty($item['DecayingModel']['parameters']['base_score_config'])) {
                $item['DecayingModel']['parameters']['base_score_config'] = new stdClass(); // force output to be {} instead of []
            }
        ?>
        <td data-toggle="json" ondblclick="document.location.href ='<?php echo $baseurl."/decayingModel/view/".$item['DecayingModel']['id']; ?>'"><?php echo json_encode($item['DecayingModel']['parameters']); ?>&nbsp;</td>
        <td><?php echo h($item['DecayingModel']['formula']); ?>&nbsp;</td>
        <td><?php echo count($item['DecayingModel']['attribute_types']); ?>&nbsp;</td>
        <td><?php echo h($item['DecayingModel']['version']); ?>&nbsp;</td>
        <td><i class="fas fa-<?php echo $item['DecayingModel']['enabled'] ? 'check' : 'times';?>"></i></td>
        <?php if ($isAclTemplate): ?>
        <td class="short action-links">
            <?php echo $this->Html->link('', array('action' => 'view', $item['DecayingModel']['id']), array('class' => 'icon-list-alt', 'title' => 'View'));?>
            <?php echo $this->Html->link('', array('action' => 'edit', $item['DecayingModel']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));?>
            <?php echo $this->Html->link('', array('action' => 'export', $item['DecayingModel']['id'] . '.json'), array('download' => true, 'class' => 'fa fa-cloud-download-alt', 'title' => __('Download model')));?>
            <?php
                if (!$item['DecayingModel']['isDefault']) {
                    echo $this->Form->postLink('', array('action' => 'delete', $item['DecayingModel']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete DecayingModel #' . $item['DecayingModel']['id'] . '?'));
                }
            ?>
            <?php
                if ($item['DecayingModel']['enabled']):
                    echo $this->Form->postLink('', array('action' => 'disable', $item['DecayingModel']['id']), array('class' => 'fa fa-pause', 'title' => 'Disable model'), __('Are you sure you want to disable DecayingModel #' . $item['DecayingModel']['id'] . '?'));
                else:
                    echo $this->Form->postLink('', array('action' => 'enable', $item['DecayingModel']['id']), array('class' => 'fa fa-play', 'title' => 'Enable model'), __('Are you sure you want to enable DecayingModel #' . $item['DecayingModel']['id'] . '?'));
                endif;
            ?>
        </td>
        <?php endif; ?>
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

<script>
$(document).ready(function() {

});
function prettyPrintJson() {
    $('[data-toggle=\"json\"]').each(function() {
        $(this).attr('data-toggle', '')
            .html(syntaxHighlightJson($(this).text().trim()));
    });
}
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'index'));
?>
