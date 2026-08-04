<div>
    <label for="toggleTableDBIndexes" style="display: inline-block;">
        <input type="checkbox" id="toggleTableDBIndexes" class="form-input" checked>
        <?php echo __('Show database indexes') ?>
    </label>
</div>
<div id="containerDBIndexes" class="" style="max-height: 800px; overflow-y: auto; padding: 5px;">
    <?php if(empty($diagnostic)): ?>
        <span class="label label-success"><?php echo __('Index diagnostic:'); ?> <i class="fa fa-check"></i></span>
    <?php else: ?>
        <div class="alert alert-warning">
            <strong><?php echo __('Notice'); ?></strong>
            <?php echo __('The highlighted issues may be benign. if you are unsure, please open an issue and ask for clarification.'); ?>
        </div>
        <table id="tableDBIndexes" class="table table-condensed table-bordered">
            <thead>
                <tr>
                    <th>Table name</th>
                    <th>Column name</th>
                    <th>Indexed</th>
                    <th>Description</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach($columnPerTable as $tableName => $columnArray): ?>
                    <?php 
                        $columnCount = 0;
                        $rowHtml = '';
                    ?>
                    <?php foreach($columnArray as $columnName): ?>
                        <?php 
                            $columnIndexed = isset($indexes[$tableName][$columnName]);
                            $warningArray = isset($diagnostic[$tableName][$columnName]);
                            if ($warningArray) {
                                $columnCount++;
                            }
                            $rowHtml .= sprintf('%s%s%s%s%s%s',
                                sprintf('<tr class="%s">', $warningArray ? 'error' : 'indexInfo hidden'),
                                sprintf('<td>%s</td>', h($columnName)),
                                sprintf('<td><i class="bold fa %s"></i></td>', $columnIndexed ? 'green fa-check' : 'red fa-times'),
                                sprintf('<td>%s</td>', $warningArray ? h($diagnostic[$tableName][$columnName]['message']) : ''),
                                sprintf('<td>%s</td>', $warningArray ?
                                    sprintf(
                                        '<i class="fa fa-wrench useCursorPointer" onclick="quickFixIndexSchema(this, \'%s\')" title="%s" aria-label="%s" tabindex="0" role="link" data-query="%s"></i>',
                                        h($diagnostic[$tableName][$columnName]['sql']),
                                        __('Fix Database Index Schema'),
                                        __('Fix Database Index Schema'),					
                                        h($diagnostic[$tableName][$columnName]['sql'])
                                    ) : ''
                                ),
                                '</tr>'
                            );
                        ?>
                    <?php endforeach; ?>
                    <?php if ($columnCount > 0): ?>
                        <?php echo sprintf('<tr><td rowspan="%s" colspan="0" class="bold">%s</td></tr>', $columnCount+1, h($tableName)); ?>
                        <?php echo $rowHtml; ?>
                    <?php endif; ?>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<script>
    $(document).ready(function() {
        $('#toggleTableDBIndexes').change(function() {
            $('#containerDBIndexes').toggle();
        })
    })
    function quickFixIndexSchema(clicked, sqlQuery) {
        var message = "<?php echo sprintf('<div class=\"alert alert-error\" style=\"margin-bottom: 5px;\"><h5>%s</h5> %s</div>', __('Warning'), __('Executing this query might take some time and may harm your database. Please review the query below or backup your database in case of doubt.')) ?>"
        message += "<div class=\"well\"><kbd>" + sqlQuery + "</kbd></div>"
        openPopover(clicked, message, undefined, 'left');
    }
</script>
