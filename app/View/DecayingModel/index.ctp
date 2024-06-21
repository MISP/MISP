<div class="templates index">
    <h2><?php echo __('Decaying Models');?></h2>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>

<?php
    $temp = $passedArgsArray;
    unset($temp['sort']);
    unset($temp['direction']);
    $filter_active = count(array_keys($temp)) > 0;
    $data = array(
        'children' => array(
            array(
                'children' => array(
                    array(
                        'title' => __('All Models'),
                        'text' => __('All Models'),
                        'url' => sprintf('%s/%s%s',
                            $baseurl . '/decayingModel/index',
                            isset($passedArgsArray['sort']) ? 'sort:' . $passedArgsArray['sort'] . '/' : '',
                            isset($passedArgsArray['direction']) ? 'direction:' . $passedArgsArray['direction'] . '/' : ''
                        ),
                        'class' => 'searchFilterButton',
                        'active' => !$filter_active
                    ),
                    array(
                        'title' => __('My models only'),
                        'text' => __('My Models'),
                        'url' => sprintf('%s/%s%s%s',
                            $baseurl . '/decayingModel/index',
                            isset($passedArgsArray['sort']) ? 'sort:' . $passedArgsArray['sort'] . '/' : '',
                            isset($passedArgsArray['direction']) ? 'direction:' . $passedArgsArray['direction'] . '/' : '',
                            'my_models:' . (!isset($passedArgsArray['my_models']) || !$passedArgsArray['my_models'] ? '1' : '0')
                        ),
                        'class' => 'searchFilterButton',
                        'active' => isset($passedArgsArray['my_models']) && $passedArgsArray['my_models']
                    ),
                    array(
                        'title' => __('Models available to everyone'),
                        'text' => __('Shared Models'),
                        'url' => sprintf('%s/%s%s%s',
                            $baseurl . '/decayingModel/index',
                            isset($passedArgsArray['sort']) ? 'sort:' . $passedArgsArray['sort'] . '/' : '',
                            isset($passedArgsArray['direction']) ? 'direction:' . $passedArgsArray['direction'] . '/' : '',
                            'all_orgs:' . (!isset($passedArgsArray['all_orgs']) || !$passedArgsArray['all_orgs'] ? '1' : '0')
                        ),
                        'class' => 'searchFilterButton',
                        'active' => isset($passedArgsArray['all_orgs']) && $passedArgsArray['all_orgs']
                    ),
                    array(
                        'title' => __('Default models only'),
                        'text' => __('Default Models'),
                        'url' => sprintf('%s/%s%s%s',
                            $baseurl . '/decayingModel/index',
                            isset($passedArgsArray['sort']) ? 'sort:' . $passedArgsArray['sort'] . '/' : '',
                            isset($passedArgsArray['direction']) ? 'direction:' . $passedArgsArray['direction'] . '/' : '',
                            'default_models:' . (!isset($passedArgsArray['default_models']) || !$passedArgsArray['default_models'] ? '1' : '0')
                        ),
                        'class' => 'searchFilterButton',
                        'active' => isset($passedArgsArray['default_models']) && $passedArgsArray['default_models']
                    ),
                )
            )
        )
    );
    echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data));
?>

    <table class="table table-striped table-hover table-condensed">
    <tr>
            <th><?php echo $this->Paginator->sort('ID');?></th>
            <th><?php echo $this->Paginator->sort('org', __('Organization'));?></th>
            <th><?php echo $this->Paginator->sort('all_orgs', __('Usable to everyone'));?></th>
            <th><?php echo $this->Paginator->sort('name', __('Name'));?></th>
            <th><?php echo $this->Paginator->sort('description', __('Description'));?></th>
            <th>
                <?php echo __('Parameters'); ?>
                <a class="useCursorPointer" title="<?php echo __('Pretty print') ?>"><b style="font-size: larger;" onclick="prettyPrintJson();">{ }</b></a>

            </th>
            <th><?php echo $this->Paginator->sort('formula', __('Formula'));?></th>
            <th><?php echo __('# Assigned Types') ?></th>
            <th><?php echo $this->Paginator->sort('version', __('Version'));?></th>
            <th><?php echo $this->Paginator->sort('enabled', __('Enabled'));?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr><?php
foreach ($decayingModels as $item): ?>
    <tr>
        <td class="short"><a href="<?php echo $baseurl."/decayingModel/view/" . h($item['DecayingModel']['id']); ?>"><?php echo h($item['DecayingModel']['id']); ?>&nbsp;</a></td>
        <td class="short">
            <?php
                echo $this->OrgImg->getOrgImg(array('name' => $item['DecayingModel']['org_id'], 'size' => 24));
            ?>
            &nbsp;
        </td>
        <td><i class="fas fa-<?php echo $item['DecayingModel']['all_orgs'] ? 'check' : 'times';?>"></i></td>
        <td>
            <a href="<?php echo $baseurl."/decayingModel/view/" . h($item['DecayingModel']['id']); ?>"><?php echo h($item['DecayingModel']['name']); ?>&nbsp;</a>
            <?php if ($item['DecayingModel']['default']): ?>
                <img src="<?php echo $baseurl;?>/img/MISP.png" width="24" height="24" style="padding-bottom:3px;" title="<?php echo __('Default Model from MISP Project'); ?>" />
            <?php endif; ?>
        </td>
        <td><?php echo h($item['DecayingModel']['description']); ?>&nbsp;</td>
        <?php
            if (isset($item['DecayingModel']['parameters']['base_score_config']) && empty($item['DecayingModel']['parameters']['base_score_config'])) {
                $item['DecayingModel']['parameters']['base_score_config'] = new stdClass(); // force output to be {} instead of []
            }
        ?>
        <td data-toggle="json" ondblclick="document.location.href ='<?php echo $baseurl . '/decayingModel/view/' . h($item['DecayingModel']['id']); ?>'"><?php echo h(json_encode($item['DecayingModel']['parameters'])); ?>&nbsp;</td>
        <td>
            <?php echo h($item['DecayingModel']['formula']); ?>
            <?php if (isset($available_formulas[$item['DecayingModel']['formula']]['description'])): ?>
                <i class="fas fa-question-circle" data-toggle="tooltip" title="<?php echo h($available_formulas[$item['DecayingModel']['formula']]['description']); ?>"></i>
            <?php else: ?>
                &nbsp
            <?php endif; ?>
        </td>
        <td><?php echo count($item['DecayingModel']['attribute_types']); ?>&nbsp;</td>
        <td><?php echo h($item['DecayingModel']['version']); ?>&nbsp;</td>
        <td><i class="fas fa-<?php echo $item['DecayingModel']['enabled'] ? 'check' : 'times';?>"></i></td>
        <td class="short action-links">
            <?php echo $this->Html->link('', array('action' => 'view', $item['DecayingModel']['id']), array('class' => 'icon-list-alt', 'title' => 'View'));?>
            <?php echo $this->Html->link('', array('action' => 'export', $item['DecayingModel']['id'] . '.json'), array('download' => true, 'class' => 'fa fa-cloud-download-alt', 'title' => __('Download model')));?>
            <?php if ($me['Role']['perm_admin']): ?>
                <?php if ($me['Role']['perm_site_admin'] || $item['DecayingModel']['org_id'] == $me['org_id']): ?>
                    <?php
                        if (!$item['DecayingModel']['default']) {
                            echo $this->Form->postLink('', array('action' => 'delete', $item['DecayingModel']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete DecayingModel #' . h($item['DecayingModel']['id']) . '?'));
                        }
                    ?>
                    <?php echo $this->Html->link('', array('action' => 'edit', $item['DecayingModel']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));?>
                    <?php
                        if ($item['DecayingModel']['enabled']):
                            echo $this->Form->postLink('', array('action' => 'disable', $item['DecayingModel']['id']), array('class' => 'fa fa-pause', 'title' => 'Disable model'), __('Are you sure you want to disable DecayingModel #' . h($item['DecayingModel']['id']) . '?'));
                        else:
                            echo $this->Form->postLink('', array('action' => 'enable', $item['DecayingModel']['id']), array('class' => 'fa fa-play', 'title' => 'Enable model'), __('Are you sure you want to enable DecayingModel #' . h($item['DecayingModel']['id']) . '?'));
                        endif;
                    ?>
                <?php endif; ?>
            <?php endif; ?>
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

<script>
$(document).ready(function() {
    $('[data-toggle="tooltip"]').tooltip();
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
