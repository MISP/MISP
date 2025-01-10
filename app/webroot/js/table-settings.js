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