<?php
    $tpl = isset($data['EventTemplate']) ? $data['EventTemplate'] : array();
    $org = isset($data['Organisation']) ? $data['Organisation'] : array();
    $creator = isset($data['CreatorUser']) ? $data['CreatorUser'] : array();
    $deps = isset($data['EventTemplateObjectDependency'])
        ? $data['EventTemplateObjectDependency']
        : array();
    $distLabel = ((int)($tpl['distribution'] ?? 0) === 1)
        ? __('Community')
        : __('Org only');
?>
<div class="index">
    <h2><?php echo h($tpl['name'] ?? ''); ?></h2>
    <p class="help-block">
        <?php echo __('The HTML UI for event templates ships in Phase 2 of the event-templating rollout. This page renders the raw template row for now; use the REST API for full detail.'); ?>
    </p>
    <dl class="dl-horizontal">
        <dt><?php echo __('Id'); ?></dt>
        <dd><?php echo h($tpl['id'] ?? ''); ?></dd>
        <dt><?php echo __('Uuid'); ?></dt>
        <dd><code><?php echo h($tpl['uuid'] ?? ''); ?></code></dd>
        <dt><?php echo __('Name'); ?></dt>
        <dd><?php echo h($tpl['name'] ?? ''); ?></dd>
        <dt><?php echo __('Description'); ?></dt>
        <dd><?php echo nl2br(h($tpl['description'] ?? '')); ?></dd>
        <dt><?php echo __('Organisation'); ?></dt>
        <dd><?php echo h($org['name'] ?? ''); ?></dd>
        <dt><?php echo __('Creator'); ?></dt>
        <dd><?php echo h($creator['email'] ?? ''); ?></dd>
        <dt><?php echo __('Distribution'); ?></dt>
        <dd><?php echo h($distLabel); ?></dd>
        <dt><?php echo __('Active'); ?></dt>
        <dd><?php echo ((int)($tpl['active'] ?? 0) === 1) ? __('Yes') : __('No'); ?></dd>
        <dt><?php echo __('Version'); ?></dt>
        <dd><?php echo h($tpl['version'] ?? ''); ?></dd>
        <dt><?php echo __('Created'); ?></dt>
        <dd><?php echo h($tpl['created'] ?? ''); ?></dd>
        <dt><?php echo __('Modified'); ?></dt>
        <dd><?php echo h($tpl['modified'] ?? ''); ?></dd>
    </dl>
    <?php if (!empty($deps)): ?>
        <h3><?php echo __('Object template dependencies'); ?></h3>
        <table class="table table-striped table-condensed">
            <thead>
                <tr>
                    <th><?php echo __('Name'); ?></th>
                    <th><?php echo __('Uuid'); ?></th>
                    <th><?php echo __('Pinned version'); ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($deps as $dep): ?>
                <tr>
                    <td><?php echo h($dep['object_template_name']); ?></td>
                    <td><code><?php echo h($dep['object_template_uuid']); ?></code></td>
                    <td><?php echo h($dep['pinned_version']); ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    <h3><?php echo __('Definition (JSON)'); ?></h3>
    <pre><?php echo h(JsonTool::encode($tpl['definition'] ?? array(), true)); ?></pre>
</div>
