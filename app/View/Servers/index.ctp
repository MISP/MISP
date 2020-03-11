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
            <th><?php echo __('Prio');?></th>
            <th><?php echo __('Connection test');?></th>
            <th><?php echo __('Sync user');?></th>
            <th><?php echo __('Reset API key');?></th>
            <th><?php echo $this->Paginator->sort('internal');?></th>
            <th><?php echo $this->Paginator->sort('push');?></th>
            <th><?php echo $this->Paginator->sort('pull');?></th>
            <th><?php echo $this->Paginator->sort('push_sightings', 'Push Sightings');?></th>
            <th><?php echo $this->Paginator->sort('caching_enabled', 'Cache');?></th>
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
foreach ($servers as $row_pos => $server):
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
        if ($syncOption === 'pull') {
            if (!empty($rules['pull']['url_params'])) {
                $ruleDescription[$syncOption] .= sprintf(
                    '%s: %s',
                    sprintf("<span class='bold'>%s</span>", __('URL params')),
                    sprintf(
                        "<pre class='jsonify'>%s</pre>",
                        h(json_encode(json_decode($rules['pull']['url_params']), JSON_PRETTY_PRINT))
                    )
                );
            }
        }
    }
    $arrows = '';
    foreach (['up', 'down'] as $direction) {
        $arrows .= sprintf(
            '<i class="fas fa-arrow-circle-%s rearrange-%s" aria-label="%s" title="%s" data-server-id="%s"></i>',
            $direction,
            $direction,
            $direction === 'up' ? __('Move server priority up') : __('Move server priority down'),
            $direction === 'up' ? __('Move server priority up') : __('Move server priority down'),
            $server['Server']['id']
        );
    }
?>
    <tr id="row_<?php echo h($server['Server']['id']); ?>">
        <td class="short"><?php echo h($server['Server']['id']); ?></td>
        <td>
            <?php
                if (!empty($server['Server']['name'])) echo h($server['Server']['name']);
                else echo h($server['Server']['url']);
            ?>
        </td>
        <td id="priority_<?php echo $server['Server']['id'];?>">
            <?php echo $arrows;?>
        </td>
        <td class="short" id="connection_test_<?php echo $server['Server']['id'];?>"><span role="button" tabindex="0" aria-label="<?php echo __('Test the connection to the remote instance');?>" title="<?php echo __('Test the connection to the remote instance');?>" class="btn btn-primary" style="line-height:10px; padding: 4px 4px;" onClick="testConnection('<?php echo $server['Server']['id'];?>');"><?php echo __('Run');?></span></td>
        <td class="short" id="sync_user_test_<?php echo $server['Server']['id'];?>"><span role="button" tabindex="0" aria-label="<?php echo __('View the sync user of the remote instance');?>" title="<?php echo __('View the sync user of the remote instance');?>" class="btn btn-primary" style="line-height:10px; padding: 4px 4px;" onClick="getRemoteSyncUser('<?php echo $server['Server']['id'];?>');"><?php echo __('View');?></span></td>
        <td id="reset_api_key_<?php echo $server['Server']['id'];?>">
            <?php
                echo $this->Form->postLink(
                    __('Reset'),
                    $baseurl . '/servers/resetRemoteAuthKey/' . $server['Server']['id'],
                    array(
                        'style' => 'line-height:10px; padding: 4px 4px;',
                        'title' => __('Remotely reset API key'),
                        'aria-label' => __('Remotely reset API key'),
                        'class' => 'btn btn-primary'
                    )
                );
            ?>
        </td>

<td><span class="<?php echo ($server['Server']['internal']? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['internal']? __('Yes') : __('No')); ?>" title="<?php echo ($server['Server']['internal']? __('Internal instance that ignores distribution level degradation *WARNING: Only use this setting if you have several internal instances and the sync link is to an internal extension of the current MISP community*') : __('Normal sync link to an external MISP instance. Distribution degradation will follow the normal rules.')); ?>"></span></td>
        <td><span class="<?php echo ($server['Server']['push']? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['push']? __('Yes') : __('No')); ?>"></span><span class="short <?php if (!$server['Server']['push'] || empty($ruleDescription['push'])) echo "hidden"; ?>" data-toggle="popover" title="Distribution List" data-content="<?php echo $ruleDescription['push']; ?>"> (<?php echo __('Rules');?>)</span></td>
        <td><span class="<?php echo ($server['Server']['pull']? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['pull']? __('Yes') : __('No')); ?>"></span><span class="short <?php if (!$server['Server']['pull'] || empty($ruleDescription['pull'])) echo "hidden"; ?>" data-toggle="popover" title="Distribution List" data-content="<?php echo $ruleDescription['pull']; ?>"> (<?php echo __('Rules');?>)</span></td>
        <td class="short"><span class="<?php echo ($server['Server']['push_sightings'] ? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['push_sightings'] ? __('Yes') : __('No')); ?>"></span></td>
        <td>
            <?php
                if ($server['Server']['caching_enabled']) {
                    if (!empty($server['Server']['cache_timestamp'])) {
                        $units = array('m', 'h', 'd');
                        $intervals = array(60, 60, 24);
                        $unit = 's';
                        $last = time() - $server['Server']['cache_timestamp'];
                        foreach ($units as $k => $v) {
                            if ($last > $intervals[$k]) {
                                $unit = $v;
                                $last = floor($last / $intervals[$k]);
                            } else {
                                break;
                            }
                        }
                        echo sprintf(
                            '<span class="blue bold">%s%s%s</span> %s',
                            __('Age: '),
                            $last,
                            $unit,
                            '<span class="icon-ok"></span>'
                        );
                    } else {
                        echo sprintf(
                            '<span class="red bold">%s</span> %s',
                            __('Not cached'),
                            '<span class="icon-ok"></span>'
                        );
                    }
                } else {
                    echo '<span class="icon-remove" role="img" aria-label="' . __('No') . '"></span>';
                }
            ?>
        </td>
        <td class="short"><span class="<?php echo ($server['Server']['unpublish_event'] ? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['unpublish_event'] ? __('Yes') : __('No')); ?>"></span></td>
        <td class="short"><span class="<?php echo ($server['Server']['publish_without_email'] ? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['publish_without_email'] ? __('Yes') : __('No')); ?>"></span></td>
        <td><?php echo h($server['Server']['url']); ?>&nbsp;</td>
        <td><a href="/organisations/view/<?php echo h($server['RemoteOrg']['id']); ?>"><?php echo h($server['RemoteOrg']['name']); ?></a></td>
        <td class="short"><?php echo h($server['Server']['cert_file']); ?>&nbsp;</td>
        <td class="short"><?php echo h($server['Server']['client_cert_file']); ?>&nbsp;</td>
        <td class="short"><span class="<?php echo ($server['Server']['self_signed'] ? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['self_signed'] ? __('Yes') : __('No')); ?>"></span></td>
        <td class="short"><span class="<?php echo ($server['Server']['skip_proxy'] ? 'icon-ok' : 'icon-remove'); ?>" role="img" aria-label="<?php echo ($server['Server']['skip_proxy'] ? __('Yes') : __('No')); ?>"></span></td>
        <td class="short"><a href="/organisations/view/<?php echo h($server['Organisation']['id']); ?>"><?php echo h($server['Organisation']['name']); ?></a></td>
        <td class="short action-links">
            <?php
                echo sprintf('<a href="%s" title="%s" aria-label="%s" class="%s"></a>', $baseurl . '/servers/previewIndex/' . h($server['Server']['id']), __('Explore'), __('Explore'), 'fa fa-search');
                if ($server['Server']['pull']) {
                    echo sprintf('<a href="%s" title="%s" aria-label="%s" class="%s"></a>', $baseurl . '/servers/pull/' . h($server['Server']['id']) . '/update', __('Pull updates to events that already exist locally'), __('Pull updates'), 'fa fa-sync');
                    echo sprintf('<a href="%s" title="%s" aria-label="%s" class="%s"></a>', $baseurl . '/servers/pull/' . h($server['Server']['id']) . '/full', __('Pull all'), __('Pull all'), 'fa fa-arrow-circle-down');
                }
                if ($server['Server']['push'] || $server['Server']['push_sightings']) {
                    echo sprintf('<a href="%s" title="%s" aria-label="%s" class="%s"></a>', $baseurl . '/servers/push/' . h($server['Server']['id']) . '/full', __('Push all'), __('Push all'), 'fa fa-arrow-circle-up');
                }
                if ($server['Server']['caching_enabled']) {
                        echo sprintf('<a href="%s" title="%s" aria-label="%s" class="%s"></a>', $baseurl . '/servers/cache/' . h($server['Server']['id']), __('Cache instance'), __('Cache instance'), 'fa fa-memory');
                }
                $mayModify = ($isSiteAdmin);
                if ($mayModify) {
                    echo sprintf('<a href="%s" title="%s" aria-label="%s" class="%s"></a>', $baseurl . '/servers/edit/' . h($server['Server']['id']), __('Edit'), __('Edit'), 'fa fa-edit');
                    echo $this->Form->postLink('', array('action' => 'delete', $server['Server']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete # %s?', $server['Server']['id']));
                }
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
        $('.rearrange-up').click(function() {
            moveIndexRow($(this).data('server-id'), 'up', '/servers/changePriority');
        });
        $('.rearrange-down').click(function() {
            moveIndexRow($(this).data('server-id'), 'down', '/servers/changePriority');
        });
    });
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'index'));
