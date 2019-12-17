<label for="toggleTableDBIndexes">
    <input type="checkbox" id="toggleTableDBIndexes" class="form-input"></input>
    <?php echo __('Show database indexes') ?>
</label>
<div id="tableDBIndexes" class="hidden" style="max-height: 800px; overflow-y: auto; padding: 5px;">
    <table class="table table-condensed table-bordered">
        <thead>
            <tr>
                <th>Table name</th>
                <th>Column name</th>
                <th>Indexed</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach($columnPerTable as $tableName => $columnArray): ?>
                <tr>
                    <?php echo sprintf('<td rowspan="%s" colspan="0" class="bold">%s</td>', count($columnArray)+1, h($tableName)); ?>
                </tr>
                <?php foreach($columnArray as $columnName): ?>
                    <?php $columnIndexed = !empty($indexes[$tableName]) && in_array($columnName, $indexes[$tableName]) ?>
                    <tr class="<?php echo $columnIndexed ? '' : 'warning'; ?>">
                        <td><?php echo h($columnName); ?></td>
                        <td><i class="bold fa <?php echo $columnIndexed ? 'green fa-check' : 'red fa-times'; ?>"></i></td>
                    </tr>
                <?php endforeach; ?>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<script>
    $(document).ready(function() {
        $('#toggleTableDBIndexes').change(function() {
            $('#tableDBIndexes').toggle();
        })
    })
</script>