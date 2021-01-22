<?php
$formatValue = function($value) {
    if (mb_strlen($value) > 64) {
        $value = mb_substr($value, 0, 64) . '...';
    }
    return h(json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
};

$removeActions = [
    AuditLog::ACTION_DELETE => true,
    AuditLog::ACTION_REMOVE_GALAXY_LOCAL => true,
    AuditLog::ACTION_REMOVE_GALAXY => true,
    AuditLog::ACTION_REMOVE_TAG => true,
    AuditLog::ACTION_REMOVE_TAG_LOCAL => true,
];

?><div class="logs index">
<h2><?= __('Audit logs for event #%s', $event['Event']['id']) ?></h2>
    <div class="pagination">
        <ul>
            <?php
            $paginator = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            $paginator .= $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            $paginator .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $paginator;
            ?>
            <li><a href="<?= $baseurl . '/logs/event_index/' . h($event['Event']['id']) ?>"><?= __('Older logs') ?></a></li>
        </ul>
    </div>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?= $this->Paginator->sort('created');?></th>
            <th><?= $this->Paginator->sort('user_id', __('User'));?></th>
            <th><?= $this->Paginator->sort('org_id', __('Org'));?></th>
            <th><?= $this->Paginator->sort('action');?></th>
            <th>Model</th>
            <th>Title</th>
            <th>Change</th>
        </tr>
        <?php foreach ($list as $item): ?>
        <tr>
            <td class="short"><?= h($item['AuditLog']['created']); ?></td>
            <td class="short"><?php
                if (isset($item['AuditLog']['user_id']) && $item['AuditLog']['user_id'] == 0) {
                    echo __('SYSTEM');
                } else if (isset($item['User']['email'])) {
                    echo h($item['User']['email']);
                } ?></td>
            <td class="short"><?= isset($item['Organisation']) ? $this->OrgImg->getOrgLogo($item, 24) : '' ?></td>
            <td class="short"><?= h($item['AuditLog']['action_human']) ?></td>
            <td class="short"><?= h($item['AuditLog']['model']) . ' #' . h($item['AuditLog']['model_id']) ?></td>
            <td class="limitedWidth"><?= h($item['AuditLog']['title']) ?></td>
            <td><?php
                if (is_array($item['AuditLog']['change'])) {
                    foreach ($item['AuditLog']['change'] as $field => $values) {
                        echo '<span class="json_key">' . h($field) . ':</span> ';
                        if (isset($removeActions[$item['AuditLog']['action']])) {
                            echo '<span class="json_string">' . $formatValue($values) . '</span> <i class="fas fa-arrow-right json_null"></i> <i class="fas fa-times json_string"></i><br>';
                        } else {
                            if (is_array($values)) {
                                echo '<span class="json_string">' . $formatValue($values[0]) . '</span> ';
                                $value = $values[1];
                            } else {
                                $value = $values;
                            }
                            echo '<i class="fas fa-arrow-right json_null"></i> <span class="json_string">' . $formatValue($value) . '</span><br>';
                        }
                    }
                }
                ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <p>
    <?= $this->Paginator->counter(array(
        'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
            <?= $paginator ?>
            <li><a href="<?= $baseurl . '/logs/event_index/' . h($event['Event']['id']) ?>"><?= __('Older logs') ?></a></li>
        </ul>
    </div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'event', 'menuItem' => 'eventLog', 'event' => $event, 'mayModify' => $mayModify]);

