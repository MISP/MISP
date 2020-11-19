<?php if (!isset($drawToggleButton) || $drawToggleButton): ?>
<div style="margin-top: -12px; margin-bottom: 12px;">
    <button id="toggleElementUI" type="button" class="btn btn-primary"><?= __('Toggle Cluster Elements UI'); ?></button>
</div>
<?php endif; ?>

<div id="genericModal" class="modal hide fade">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h3><?= __('Edit Cluster\'s Elements') ?></h3>
    </div>
    <div class="modal-body">
        <table class="table table-condensed" style="margin-bottom: 0;">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody id="elementTableBody">
                <?php if (false): ?>
                    <tr>
                        <td><input type="text" value="<?= h($element['key']) ?>"></input></td>
                        <td><input type="text" value="<?= h($element['value']) ?>"></input></td>
                        <td><buton type="button" class="btn btn-danger btn-small" onclick="deleteCurrentRow(this)">&times;</buton></td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
        <button onclick="addNewRow()" type="button" class="btn btn-primary btn-small bold">+ <?= __('Add Element'); ?></button>
    </div>
    <div class="modal-footer">
        <button id="injectElements" type="button" class="btn btn-primary btn-small" data-dismiss="modal"><?= __('Save changes'); ?></button>
        <a href="#" class="btn" data-dismiss="modal"><?= __('Close'); ?></a>
  </div>
</div>

<script>
    var currentElements = <?= json_encode($elements) ?>;
    $(document).ready(function() {
        $('#injectElements').click(function() {
            currentElements = parseTable();
            $('#GalaxyClusterElements').text(JSON.stringify(currentElements))
        });
        $('#toggleElementUI').click(function() {
            initClusterElementUI();
        });
    });

    function initClusterElementUI() {
        $('#genericModal').modal();
        deleteAllRows();
        fillTable(currentElements);
    }

    function addNewRow(key, value) {
        key = key === undefined ? '' : key;
        value = value === undefined ? '' : value;
        $('#elementTableBody').append($('<tr></tr>').append(
            $('<td></td>').append($('<input type="text" class="elementKey"></input>').val(key)),
            $('<td></td>').append($('<input type="text" class="elementValue"></input>').val(value)),
            $('<td></td>').append('<buton type="button" class="btn btn-danger btn-small" onclick="deleteCurrentRow(this)">&times;</buton>'),
        ))
    }

    function deleteAllRows() {
        $('#elementTableBody tr').remove();
    }

    function deleteCurrentRow(clicked) {
        $(clicked).closest('tr').remove();
    }

    function parseTable() {
        var elements = [];
        $('#elementTableBody > tr').each(function(i, row) {
            var row = $(row);
            var k = row.find('.elementKey').val();
            var v = row.find('.elementValue').val();
            if (k !== '' && v !== '') {
                elements.push({
                    key: k,
                    value: v
                });
            }
        })
        return elements;
    }

    function fillTable(dict) {
        dict.forEach(function(entry) {
            addNewRow(entry.key, entry.value);
        })
    }
</script>
