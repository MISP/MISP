<?php
/*
 *  Toggle element - a simple checkbox with the current state selected
 *  On click, issues a GET to a given endpoint, retrieving a form with the
 *  value flipped, which is immediately POSTed.
 *  to fetch it.
 *  Options:
 *      - url: The URL on which to perform the POST
 *      - url_params_vars: Variables to be injected into the URL using the DataFromPath helper
 *      - toggle_data.skip_full_reload: If true, the index will not be reloaded and the checkbox will be flipped on success
 *      - toggle_data.editRequirement.function: A function to be called to assess if the checkbox can be toggled
 *      - toggle_data.editRequirement.options: Option that will be passed to the function
 *      - toggle_data.editRequirement.options.datapath: If provided, entries will have their datapath values converted into their extracted value
 *      - toggle_data.confirm.[enable/disable].title: 
 *      - toggle_data.confirm.[enable/disable].titleHtml: 
 *      - toggle_data.confirm.[enable/disable].body: 
 *      - toggle_data.confirm.[enable/disable].bodyHtml: 
 *      - toggle_data.confirm.[enable/disable].type: 
 *
 */
    $data = $this->Hash->get($row, $field['data_path']);
    $seed = rand();
    $checkboxId = 'GenericToggle-' . $seed;
    $tempboxId = 'TempBox-' . $seed;

    $requirementMet = false;
    if (isset($field['toggle_data']['editRequirement'])) {
        if (isset($field['toggle_data']['editRequirement']['options']['datapath'])) {
            foreach ($field['toggle_data']['editRequirement']['options']['datapath'] as $name => $path) {
                $field['toggle_data']['editRequirement']['options']['datapath'][$name] = empty($this->Hash->extract($row, $path)[0]) ? null : $this->Hash->extract($row, $path)[0];
            }
        }
        $options = isset($field['toggle_data']['editRequirement']['options']) ? $field['toggle_data']['editRequirement']['options'] : array();
        $requirementMet = $field['toggle_data']['editRequirement']['function']($row, $options);
    }

    echo sprintf(
        '<input type="checkbox" id="%s" class="change-cursor" %s %s><span id="%s" class="d-none"></span>',
        $checkboxId,
        empty($data) ? '' : 'checked',
        $requirementMet ? '' : 'disabled="disabled"',
        $tempboxId
    );

    // inject variables into the strings
    if (!empty($field['toggle_data']['confirm'])) {
        $field['toggle_data']['confirm']['enable']['arguments'] = isset($field['toggle_data']['confirm']['enable']['arguments']) ? $field['toggle_data']['confirm']['enable']['arguments'] : [];
        $field['toggle_data']['confirm']['disable']['arguments'] = isset($field['toggle_data']['confirm']['disable']['arguments']) ? $field['toggle_data']['confirm']['disable']['arguments'] : [];
        $stringArrayEnable = $field['toggle_data']['confirm']['enable'];
        unset($stringArrayEnable['arguments']);
        $stringArrayDisable = $field['toggle_data']['confirm']['disable'];
        unset($stringArrayDisable['arguments']);
        $confirmOptions = [
            'enable' => $this->DataFromPath->buildStringsInArray($stringArrayEnable, $row, $field['toggle_data']['confirm']['enable']['arguments'], ['highlight' => true]),
            'disable' => $this->DataFromPath->buildStringsInArray($stringArrayDisable, $row, $field['toggle_data']['confirm']['disable']['arguments'], ['highlight' => true]),
        ];
    }
    $url = $this->DataFromPath->buildStringFromDataPath($field['url'], $row, $field['url_params_vars']);
?>

<?php if ($requirementMet): ?>
<script type="text/javascript">
(function() {
    const url = "<?= h($url) ?>"
    const confirmationOptions = <?= isset($confirmOptions) ? json_encode($confirmOptions) : 'false' ?>;
    $('#<?= $checkboxId ?>').click(function(evt) {
        evt.preventDefault()
        if(confirmationOptions !== false) {
            const correctOptions = $('#<?= $checkboxId ?>').prop('checked') ? confirmationOptions['enable'] : confirmationOptions['disable'] // Adjust modal option based on checkbox state
            const modalOptions = {
                ...correctOptions,
                APIConfirm: (tmpApi) => {
                    return submitForm(tmpApi, url)
                },
            }
            UI.modal(modalOptions)
        } else {
            const tmpApi = new AJAXApi({
                statusNode: $('#<?= $checkboxId ?>')[0]
            })
            submitForm(tmpApi, url)
        }
    })

    function submitForm(api, url) {
        const reloadUrl = '<?= isset($field['toggle_data']['reload_url']) ? $field['toggle_data']['reload_url'] : $this->Url->build(['action' => 'index']) ?>'
        return api.fetchAndPostForm(url, {}, false, true)
            .then(() => {
                <?php if (!empty($field['toggle_data']['skip_full_reload'])): ?>
                    const isChecked = $('#<?= $checkboxId ?>').prop('checked')
                    $('#<?= $checkboxId ?>').prop('checked', !$('#<?= $checkboxId ?>').prop('checked'))
                <?php else: ?>
                    UI.reload(reloadUrl, $('#table-container-<?= $tableRandomValue ?>'), $('#table-container-<?= $tableRandomValue ?> table.table'))
                <?php endif; ?>
            })
    }
}())
</script>
<?php endif; ?>