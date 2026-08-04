<table class="table table-striped table-hover table-condensed">
    <tr>
        <th><?= __('Query') ?></th>
        <th><?= __('Num. rows') ?></th>
        <th><?= __('Took (ms)') ?></th>
    </tr>
    <?php foreach ($queryLog['log'] as $query): ?>
    <tr>
        <td><?= h($query['query']) ?></td>
        <td><?= h($query['numRows']) ?></td>
        <td><?= h($query['took']) ?></td>
    </tr>
    <?php endforeach; ?>
</table>
