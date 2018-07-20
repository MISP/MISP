<div class="servers index">
    <h2><?php echo __('Servers');?></h2>
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
            <th><?php echo $this->Paginator->sort('name');?></th>
            <th><?php echo __('Connection test');?></th>
            <th><?php echo $this->Paginator->sort('internal');?></th>
            <th><?php echo $this->Paginator->sort('push');?></th>
            <th><?php echo $this->Paginator->sort('pull');?></th>
            <th><?php echo $this->Paginator->sort('unpublish_event (push event)');?></th>
            <th><?php echo $this->Paginator->sort('publish_without_email (pull event)');?></th>
            <th><?php echo $this->Paginator->sort('url');?></th>
            <th><?php echo __('Remote Organisation');?></th>
            <th><?php echo $this->Paginator->sort('cert_file');?></th>
            <th><?php echo $this->Paginator->sort('client_cert_file');?></th>
            <th><?php echo $this->Paginator->sort('self_signed');?></th>
            <th><?php echo $this->Paginator->sort('skip_proxy');?></th>
            <th><?php echo $this->Paginator->sort('org');?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr>
    <?php
foreach ($servers as $server):
    $rules = array();
    $rules['push'] = json_decode($server['Server']['push_rules'], true);
    $rules['pull'] = json_decode($server['Server']['pull_rules'], true);
    $syncOptions = array('pull', 'push');
    $fieldOptions = array('tags', 'orgs');
    $typeOptions = array('OR' => array('colour' => 'green', 'text' => 'allowed'), 'NOT' => array('colour' => 'red', 'text' => 'blocked'));
    $ruleDescription = array('pull' => '', 'push' => '');
    foreach ($syncOptions as $syncOption) {
        foreach ($fieldOptions as $fieldOption) {
            foreach ($typeOptions as $typeOption => $typeData) {
                if (isset($rules[$syncOption][$fieldOption][$typeOption]) && !empty($rules[$syncOption][$fieldOption][$typeOption])) {
                    $ruleDescription[$syncOption] .= '<span class=\'bold\'>' . ucfirst($fieldOption) . ' ' . $typeData['text'] . '</span>: <span class=\'' . $typeData['colour'] . '\'>';
                    foreach ($rules[$syncOption][$fieldOption][$typeOption] as $k => $temp) {
                        if ($k != 0) $ruleDescription[$syncOption] .= ', ';
                        if ($syncOption === 'push') $temp = $collection[$fieldOption][$temp];
                        $ruleDescription[$syncOption] .= h($temp);
                    }
                    $ruleDescription[$syncOption] .= '</span><br />';
                }
            }
        }
    }
?>
    <tr>
        <td class="short"><?php echo h($server['Server']['id']); ?></td>
        <td>
            <?php
                if (!empty($server['Server']['name'])) echo h($server['Server']['name']);
                else echo h($server['Server']['url']);
            ?>
        </td>
        <td id="connection_test_<?php echo $server['Server']['id'];?>"><span role="button" tabindex="0" aria-label="<?php echo __('Test the connection to the remote instance');?>" title="<?php echo __('Test the connection to the remote instance');?>" class="btn btn-primary" style="line-height:10px; padding: 4px 4px;" onClick="testConnection('<?php echo $server['Server']['id'];?>');"><?php echo __('Run');?></span></td>
        <td><span class="<?php echo ($server['Server']['internal']? 'icon-ok' : 'icon-remove'); ?>" title="<?php echo ($server['Server']['internal']? __('Internal instance that ignores distribution level degradation *WARNING: Only use this setting if you have several internal instances and the sync link is to an internal extension of the current MISP community*') : __('Normal sync link to an external MISP instance. Distribution degradation will follow the normal rules.')); ?>"></span></td>
        <td><span class="<?php echo ($server['Server']['push']? 'icon-ok' : 'icon-remove'); ?>"></span><span class="short <?php if (!$server['Server']['push'] || empty($ruleDescription['push'])) echo "hidden"; ?>" data-toggle="popover" title="Distribution List" data-content="<?php echo $ruleDescription['push']; ?>"> (<?php echo __('Rules');?>)</span></td>
        <td><span class="<?php echo ($server['Server']['pull']? 'icon-ok' : 'icon-remove'); ?>"></span><span class="short <?php if (!$server['Server']['pull'] || empty($ruleDescription['pull'])) echo "hidden"; ?>" data-toggle="popover" title="Distribution List" data-content="<?php echo $ruleDescription['pull']; ?>"> (<?php echo __('Rules');?>)</span>
        <td class="short"><span class="<?php echo ($server['Server']['unpublish_event'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
        <td class="short"><span class="<?php echo ($server['Server']['publish_without_email'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
        <td><?php echo h($server['Server']['url']); ?>&nbsp;</td>
        <td><a href="/organisations/view/<?php echo h($server['RemoteOrg']['id']); ?>"><?php echo h($server['RemoteOrg']['name']); ?></a></td>
        <td class="short"><?php echo h($server['Server']['cert_file']); ?>&nbsp;</td>
        <td class="short"><?php echo h($server['Server']['client_cert_file']); ?>&nbsp;</td>
        <td class="short"><span class="<?php echo ($server['Server']['self_signed'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
        <td class="short"><span class="<?php echo ($server['Server']['skip_proxy'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
        <td class="short"><a href="/organisations/view/<?php echo h($server['Organisation']['id']); ?>"><?php echo h($server['Organisation']['name']); ?></a></td>
        <td class="short action-links">
            <?php
            echo $this->Html->link('', array('action' => 'previewIndex', $server['Server']['id']), array('class' => 'icon-search', 'title' => __('Explore')));
            if ($server['Server']['pull']) {
                echo $this->Html->link('', array('action' => 'pull', $server['Server']['id'], 'update'), array('class' => 'icon-refresh', 'title' => __('Pull updates to events that already exist locally')));
                echo $this->Html->link('', array('action' => 'pull', $server['Server']['id'], 'full'), array('class' => 'icon-download', 'title' => __('Pull all')));
            }
            if ($server['Server']['push']) {
                echo $this->Html->link('', array('action' => 'push', $server['Server']['id'], 'full'), array('class' => 'icon-upload', 'title' => __('Push all')));
            }
            ?>
            &nbsp;
            <?php
            $mayModify = ($isSiteAdmin);
            if ($mayModify) echo $this->Html->link('', array('action' => 'edit', $server['Server']['id']), array('class' => 'icon-edit', 'title' => __('Edit')));
            if ($mayModify) echo $this->Form->postLink('', array('action' => 'delete', $server['Server']['id']), array('class' => 'icon-trash', 'title' => __('Delete')), __('Are you sure you want to delete # %s?', $server['Server']['id']));
            ?>

        </td>
    </tr>
    <?php
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
<script type="text/javascript">
    $(document).ready(function(){
        popoverStartup();
    });
</script>
<?php
    echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'index'));
