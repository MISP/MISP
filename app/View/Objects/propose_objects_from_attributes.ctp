<table class="table table-condensed">
    <thead>
        <tr>
            <th><?php echo __('Template ID'); ?></th>
            <th><?php echo __('Object name'); ?></th>
            <th><?php echo __('Compatiblity or missing attribute type'); ?></th>
        </tr>
    </thead>
    <tbody>
    <?php foreach ($potential_templates as $i => $potential_template): ?>
            <tr>
                <td><?php echo h($potential_template['ObjectTemplate']['id']) ?></td>
                <td><?php echo h($potential_template['ObjectTemplate']['name']) ?></td>
                <?php if ($potential_template['ObjectTemplate']['compatibility'] === true): ?>
                    <td><i class="fa fa-check"></i></td>
                <?php else: ?>
                    <td><?php echo h(implode(', ', $potential_template['ObjectTemplate']['compatibility'])); ?></td>
                <?php endif; ?>
            </tr>
    <?php endforeach; ?>
    </tbody>
<table>
