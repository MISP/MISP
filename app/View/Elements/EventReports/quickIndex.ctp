<ul>
    <?php foreach($reports as $report): ?>
        <li><a class="useCursorPointer" onclick="openGenericModal('<?= sprintf('/eventReports/viewSummary/%s', h($report['id'])) ?>')"><?= h($report['name']) ?></a></li>
    <?php endforeach; ?>
</ul>