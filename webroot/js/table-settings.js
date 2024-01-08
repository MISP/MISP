function mergeAndSaveSettings(table_setting_id, newTableSettings, automaticFeedback=true) {
    const settingName = 'ui.table_setting'
    const urlGet = `/user-settings/getMySettingByName/${settingName}`
    return AJAXApi.quickFetchJSON(urlGet).then(tableSettings => {
        tableSettings = JSON.parse(tableSettings.value)
        newTableSettings = mergeNewTableSettingsIntoOld(table_setting_id, tableSettings, newTableSettings)
        return saveTableSetting(settingName, newTableSettings, automaticFeedback)
    }).catch((e) => { // setting probably doesn't exist
        return saveTableSetting(settingName, newTableSettings, automaticFeedback)
    })
}

function mergeAndSaveSettingsWithReload(table_setting_id, tableSettings, $table) {
    mergeAndSaveSettings(table_setting_id, tableSettings, false).then((apiResult) => {
        const theToast = UI.toast({
            variant: 'success',
            title: apiResult.message,
            bodyHtml: $('<div/>').append(
                $('<span/>').text('The table needs to be reloaded for the new fields to be included.'),
                $('<button/>').addClass(['btn', 'btn-primary', 'btn-sm', 'ms-3']).text('Reload table').click(function () {
                    const reloadUrl = $table.data('reload-url');
                    UI.reload(reloadUrl, $table.closest('div[id^="table-container-"]'), $(this)).then(() => {
                        theToast.removeToast()
                    })
                }),
            ),
        })
    })
}

function registerDebouncedFunction($container, fn) {
    $dropdownButton = $container.find('button.table_setting_dropdown_button')
    if ($dropdownButton.data('debouncedFunctions') === undefined) {
        $dropdownButton.data('debouncedFunctions', [])
    }
    $dropdownButton.data('debouncedFunctions').push(fn)
}

function firePendingDebouncedFunctions(dropdownBtn) {
    $dropdownButton = $(dropdownBtn)
    if ($dropdownButton.data('debouncedFunctions') !== undefined) {
        $dropdownButton.data('debouncedFunctions').forEach(function (fn) {
            fn.flush()
        })
    }
}

function mergeNewTableSettingsIntoOld(table_setting_id, oldTableSettings, newTableSettings) {
    // Merge recursively
    tableSettings = Object.assign({}, oldTableSettings, newTableSettings)
    tableSettings[table_setting_id] = Object.assign({}, oldTableSettings[table_setting_id], newTableSettings[table_setting_id])
    return tableSettings
}

function saveTableSetting(settingName, newTableSettings, automaticFeedback=true) {
    const urlSet = `/user-settings/setMySetting/${settingName}`
    return AJAXApi.quickFetchAndPostForm(urlSet, {
        value: JSON.stringify(newTableSettings)
    }, {
        provideFeedback: false
    }).then((postResult) => {
        if (automaticFeedback) {
            UI.toast({
                variant: 'success',
                title: 'Table setting saved',
                delay: 3000
            })
        }
        return postResult
    })
}
