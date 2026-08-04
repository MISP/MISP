<?php if (!isset($drawToggleButton) || $drawToggleButton): ?>
    <div style="margin-top: -12px; margin-bottom: 12px;">
        <button id="toggleElementUI" type="button" class="btn btn-primary"><?= __('Toggle Environment Variables UI'); ?></button>
    </div>
<?php endif; ?>

<div id="genericModal2" class="modal hide fade">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h3><?= __('Edit Workflow Environment Variables') ?></h3>
    </div>
    <div class="modal-body">
        <table class="table table-condensed" style="margin-bottom: 0;">
            <thead>
                <tr>
                    <th>Variable Key Name</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody id="elementTableBody">
            </tbody>
        </table>
        <button onclick="addNewRow()" type="button" class="btn btn-primary btn-small bold">+ <?= __('Add Element'); ?></button>
    </div>
    <div class="modal-footer">
        <button id="injectElements" type="button" class="btn btn-primary btn-small"><?= __('Save changes'); ?></button>
        <a href="#" class="btn"><?= __('Close'); ?></a>
    </div>
</div>

<script>
    var currentElements = {}
    $(document).ready(function() {
        $('#injectElements').click(function(evt) {
            currentElements = parseTable();
            $('#EventEnvironmentVariables').text(JSON.stringify(currentElements))
            $('#genericModal2').modal('hide');
        });
        $('#toggleElementUI').click(function() {
            initWorkflowVariablesUI();
        });
    });

    function initWorkflowVariablesUI() {
        $('#genericModal2').modal();
        deleteAllRows();
    }

    function addNewRow(key, value) {
        key = key === undefined ? '' : key;
        value = value === undefined ? '' : value;
        $('#elementTableBody').append($('<tr></tr>').append(
            $('<td></td>').append($('<input type="text" class="elementKey"></input>').val(key)),
            $('<td></td>').append($('<input type="text" class="elementValue"></input>').val(value)),
            $('<td></td>').append('<button type="button" class="btn btn-danger btn-small" onclick="deleteCurrentRow(this)">&times;</button>'),
        ))
    }

    function deleteAllRows() {
        $('#elementTableBody tr').remove();
    }

    function deleteCurrentRow(clicked) {
        $(clicked).closest('tr').remove();
    }

    function parseTable() {
        var elements = {};
        $('#elementTableBody > tr').each(function(i, row) {
            var row = $(row);
            var k = row.find('.elementKey').val();
            var v = row.find('.elementValue').val();
            if (k !== '' && v !== '') {
                elements[k] = v
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