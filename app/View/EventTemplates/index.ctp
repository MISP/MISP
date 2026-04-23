<div class="index">
    <h2><?php echo __('Event Templates'); ?></h2>
    <p class="help-block">
        <?php echo __('The HTML UI for event templates ships in Phase 2 of the event-templating rollout. Until then, this page lists the templates visible to you; use the REST API for full CRUD.'); ?>
    </p>
    <table class="table table-striped table-hover table-condensed">
        <thead>
            <tr>
                <th><?php echo __('Id'); ?></th>
                <th><?php echo __('Name'); ?></th>
                <th><?php echo __('Uuid'); ?></th>
                <th><?php echo __('Org'); ?></th>
                <th><?php echo __('Distribution'); ?></th>
                <th><?php echo __('Active'); ?></th>
                <th><?php echo __('Version'); ?></th>
                <th><?php echo __('Modified'); ?></th>
                <th class="actions"><?php echo __('Actions'); ?></th>
            </tr>
        </thead>
        <tbody>
        <?php if (!empty($list)): ?>
            <?php foreach ($list as $row): ?>
                <?php
                    $tpl = $row['EventTemplate'];
                    $orgName = isset($row['Organisation']['name'])
                        ? $row['Organisation']['name']
                        : '';
                    $distLabel = ((int)$tpl['distribution'] === 1)
                        ? __('Community')
                        : __('Org only');
                ?>
                <tr>
                    <td><?php echo h($tpl['id']); ?></td>
                    <td>
                        <?php echo $this->Html->link(
                            h($tpl['name']),
                            array('action' => 'view', $tpl['id'])
                        ); ?>
                    </td>
                    <td><code><?php echo h($tpl['uuid']); ?></code></td>
                    <td><?php echo h($orgName); ?></td>
                    <td><?php echo h($distLabel); ?></td>
                    <td><?php echo ((int)$tpl['active'] === 1) ? __('Yes') : __('No'); ?></td>
                    <td><?php echo h($tpl['version']); ?></td>
                    <td><?php echo h($tpl['modified']); ?></td>
                    <td class="short action-links">
                        <?php echo $this->Html->link(
                            __('View'),
                            array('action' => 'view', $tpl['id'])
                        ); ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr><td colspan="9"><?php echo __('No event templates visible to you.'); ?></td></tr>
        <?php endif; ?>
        </tbody>
    </table>
</div>
