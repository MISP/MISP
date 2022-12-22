<div class="logs index">
<h2><?= __('Audit logs for event #%s', intval($event['Event']['id'])) ?></h2>
    <div class="pagination">
        <ul>
            <?php
            $paginator = $this->LightPaginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            $paginator .= $this->LightPaginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $paginator;
            ?>
            <li><a href="<?= $baseurl . '/logs/event_index/' . intval($event['Event']['id']) ?>"><?= __('Older logs') ?></a></li>
        </ul>
    </div>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?= $this->LightPaginator->sort('created') ?></th>
            <th><?= $this->LightPaginator->sort('user_id', __('User')) ?></th>
            <th><?= $this->LightPaginator->sort('org_id', __('Org')) ?></th>
            <th><?= $this->LightPaginator->sort('action') ?></th>
            <th><?= __('Model') ?></th>
            <th><?= __('Title') ?></th>
            <th><?= __('Change') ?></th>
        </tr>
        <?php foreach ($list as $item): ?>
        <tr>
            <td class="short"><?= $this->Time->time($item['AuditLog']['created']); ?></td>
            <td class="short"><?php
                if (isset($item['AuditLog']['user_id']) && $item['AuditLog']['user_id'] == 0) {
                    echo __('SYSTEM');
                } else if (isset($item['User']['email'])) {
                    echo h($item['User']['email']);
                } ?></td>
            <td class="short"><?= isset($item['Organisation']) ? $this->OrgImg->getOrgLogo($item, 24) : '' ?></td>
            <td class="short"><?= h($item['AuditLog']['action_human']) ?></td>
            <td class="short"><?= h($item['AuditLog']['model']) . ' #' . intval($item['AuditLog']['model_id']) ?></td>
            <td class="limitedWidth"><?= h($item['AuditLog']['title']) ?></td>
            <td><?= $this->element('AuditLog/change', ['item' => $item]) ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <div class="pagination">
        <ul>
            <?= $paginator ?>
            <li><a href="<?= $baseurl . '/logs/event_index/' . intval($event['Event']['id']) ?>"><?= __('Older logs') ?></a></li>
        </ul>
    </div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'event', 'menuItem' => 'eventLog']);

