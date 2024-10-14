<?php

$templateVariablesHTML = sprintf('
    <div id="templateVariableModal">
        <table class="table table-condensed" style="margin-bottom: 0;">
            <thead>
                <tr>
                    <th>Template Name</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody id="elementTableBody">
            </tbody>
        </table>
        <button onclick="addNewRow()" type="button" class="btn btn-primary btn-small bold">+ %s</button>
    </div>',
    __('Add New Variable')
);

echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'data' => [
        'title' => __('Configure Template Variables'),
        'model' => 'EventReport',
        'fields' => [
            [
                'field' => 'template_variables',
                'div' => 'input clear input-append hidden',
            ],
        ],
        'metaFields' => [
            $templateVariablesHTML,
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'confirmSubmission(this)'
        ],
    ]
]);

?>


<script>
    var currentVariables = <?= json_encode($templateVariables) ?>;
    $(document).ready(function() {
        initUI()
    });

    function initUI() {
        deleteAllRows();
        fillTable(currentVariables);
    }

    function addNewRow(key, value) {
        key = key === undefined ? '' : key;
        value = value === undefined ? '' : value;
        $('#elementTableBody').append($('<tr></tr>').append(
            $('<td class="key-cell"></td>').append(
                $('<code class="curly-char">{{</code>'),
                $('<input type="text" class="elementKey"></input>').val(key),
                $('<code class="curly-char">}}</code>'),
            ),
            $('<td class="value-cell"></td>').append(
                $('<textarea type="text" class="elementValue"></textarea>').val(value),
            ),
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
                    name: k,
                    value: v
                });
            }
        })
        return elements;
    }

    function fillTable(dict) {
        if (dict.length == 0) {
            addNewRow('', '')
        }
        dict.forEach(function(entry) {
            addNewRow(entry.name, entry.value);
        })
    }

    function confirmSubmission(clicked) {
        currentVariables = parseTable();
        $('#EventReportTemplateVariables').val(JSON.stringify(currentVariables))
        $clicked = $(clicked)
        $loading = $('<div style="display:flex; align-items: center; justify-content: center;"></div>').append(
            $('<i class="fas fa-xl fa-save fa-flip"></i> <h5 style="display: inline-block; margin-left: 0.25em;">Saving variables</h5>'),
        )
        $clicked.parent().parent().find('.modal-body').append($loading)
        submitGenericFormInPlace(function(data) {
            window.location.reload();
        });
    }
</script>

<style>
    code.curly-char {
        font-size: 1.25em;
    }
    #elementTableBody > tr input,
    #elementTableBody > tr textarea {
        margin: 0.25em;
        padding: 0.25em;
    }
    td.key-cell {
        white-space: nowrap;
    }
    input.elementKey {
        font-family: Monaco, Menlo, Consolas, "Courier New", monospace;
    }
    td.value-cell {
    }
</style>