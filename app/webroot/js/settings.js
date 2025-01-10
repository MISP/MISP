const variantFromSeverity = {
    'critical': 'danger',
    'warning': 'warning',
    'info': 'info',
}

$(document).ready(function () {
    if (
        variantFromSeverity === undefined ||
        window.settingsFlattened === undefined ||
        window.saveSettingURL === undefined
    ) {
        console.error('`settingFlatenned` and `saveSettingURL` variables must be set')
    }

    if (document.getElementsByClassName('.depends-on-icon').length > 0) {
        new bootstrap.Tooltip('.depends-on-icon', {
            placement: 'right',
        })
    }
    $('select.form-select[multiple]').select2()

    $('.settings-tabs a[data-bs-toggle="tab"]').on('shown.bs.tab', function (event) {
        $('[data-bs-spy="scroll"]').trigger('scroll.bs.scrollspy')
    })

    $('.tab-content input, .tab-content select').on('input', function () {
        if ($(this).attr('type') == 'checkbox') {
            const $input = $(this)
            const $inputGroup = $(this).closest('.setting-group')
            const settingName = $(this).data('setting-name')
            const settingValue = $(this).is(':checked') ? 1 : 0
            saveAndUpdateSetting($inputGroup[0], $input, settingName, settingValue)
        } else {
            handleSettingValueChange($(this))
        }
    })

    $('.tab-content .setting-group .btn-save-setting').click(function () {
        const $input = $(this).closest('.input-group').find('input, select')
        const settingName = $input.data('setting-name')
        const settingValue = $input.val()
        saveAndUpdateSetting(this, $input, settingName, settingValue)
    })
    $('.tab-content .setting-group .btn-reset-setting').click(function () {
        const $btn = $(this)
        const $input = $btn.closest('.input-group').find('input, select')
        let oldValue = window.settingsFlattened[$input.data('setting-name')].value
        if ($input.is('select')) {
            oldValue = oldValue !== undefined ? oldValue : -1
        } else {
            oldValue = oldValue !== undefined ? oldValue : ''
        }
        $input.val(oldValue)
        if ($input.is('select') && $input.prop('multiple')) {
            $input.trigger('change')
        }
        handleSettingValueChange($input)
    })

    const referencedID = window.location.hash
    redirectToSetting(referencedID)
})

function saveAndUpdateSetting(statusNode, $input, settingName, settingValue) {
    if ($input.is('select') && $input.prop('multiple')) {
        settingValue = JSON.stringify(settingValue)
    }
    saveSetting(statusNode, settingName, settingValue).then((result) => {
        window.settingsFlattened[settingName] = result.data
        if ($input.attr('type') == 'checkbox') {
            $input.prop('checked', result.data.value == true)
        } else {
            $input.val(result.data.value)
        }
        handleSettingValueChange($input)
    }).catch((e) => { })
}

function handleSettingValueChange($input) {
    let oldValue = window.settingsFlattened[$input.data('setting-name')].value
    let newValue
    if ($input.attr('type') == 'checkbox') {
        newValue = $input.is(':checked')
    } else {
        newValue = $input.val()
    }
    if ($input.attr('type') == 'checkbox') {
        oldValue = oldValue == true
    }
    let hasChanged = newValue != oldValue
    if ($input.is('select') && $input.prop('multiple')) {
        hasChanged = !arrayEqual(oldValue, newValue)
    }
    if (!hasChanged || (newValue == '' && oldValue == undefined)) {
        restoreWarnings($input)
    } else {
        removeWarnings($input)
    }
}

function removeWarnings($input) {
    const $inputGroup = $input.closest('.input-group')
    const $btnSettingAction = $inputGroup.find('.btn-setting-action')
    const $saveButton = $('.setting-group button.btn-save-setting')
    $input.removeClass(['is-invalid', 'border-warning', 'border-danger', 'border-info', 'warning', 'info'])
    $btnSettingAction.removeClass('d-none')
    if ($input.is('select') && $input.find('option:selected').data('is-empty-option') == 1) {
        $btnSettingAction.addClass('d-none') // hide save button if empty selection picked
    }
    $inputGroup.parent().find('.invalid-feedback').removeClass('d-block')
}

function restoreWarnings($input) {
    const $inputGroup = $input.closest('.input-group')
    const $btnSettingAction = $inputGroup.find('.btn-setting-action')
    const $saveButton = $('.setting-group button.btn-save-setting')
    const setting = window.settingsFlattened[$input.data('setting-name')]
    if (setting.error) {
        borderVariant = setting.severity !== undefined ? variantFromSeverity[setting.severity] : 'warning'
        $input.addClass(['is-invalid', `border-${borderVariant}`, borderVariant])
        $inputGroup.parent().find('.invalid-feedback').addClass('d-block').text(setting.errorMessage)
    } else {
        removeWarnings($input)
    }
    const $callout = $input.closest('.settings-group')
    updateCalloutColors($callout)
    $btnSettingAction.addClass('d-none')
}

function updateCalloutColors($callout) {
    if ($callout.length == 0) {
        return
    }
    const $settings = $callout.find('input, select')
    const settingNames = Array.from($settings).map((i) => {
        return $(i).data('setting-name')
    })
    const severityMapping = { null: 0, info: 1, warning: 2, critical: 3 }
    const severityMappingInverted = Object.assign({}, ...Object.entries(severityMapping).map(([k, v]) => ({ [v]: k })))
    let highestSeverity = severityMapping[null]
    settingNames.forEach(name => {
        if (window.settingsFlattened[name].error) {
            highestSeverity = severityMapping[window.settingsFlattened[name].severity] > highestSeverity ? severityMapping[window.settingsFlattened[name].severity] : highestSeverity
        }
    });
    highestSeverity = severityMappingInverted[highestSeverity]
    $callout.removeClass(['callout', 'callout-danger', 'callout-warning', 'callout-info'])
    if (highestSeverity !== null) {
        $callout.addClass(['callout', `callout-${variantFromSeverity[highestSeverity]}`])
    }
}

function redirectToSetting(referencedID) {
    const $settingToFocus = $(referencedID)
    const pageNavID = $(referencedID).closest('.tab-pane').attr('aria-labelledby')
    const $navController = $(`#${pageNavID}`)
    const $settingGroup = $settingToFocus.closest('.settings-group')
    $navController
        .on('shown.bs.tab.after-redirect', () => {
            $settingToFocus[0].scrollIntoView()
            const inputID = $settingToFocus.parent().attr('for')
            $settingToFocus.closest('.setting-group').find(`#${inputID}`).focus()
            $navController.off('shown.bs.tab.after-redirect')
            $settingGroup.addClass(['to-be-slided', 'slide-in'])
        })
        .tab('show')
    $settingGroup.on('webkitAnimationEnd oanimationend msAnimationEnd animationend', function () {
        $(this).removeClass(['to-be-slided', 'slide-in'])
    });
}