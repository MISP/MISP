<select id="search-settings" class="d-block w-100 form-select" aria-describedby="<?= __('Search setting input') ?>"><option></option></select>

<script>
    let selectData = []
    for (const settingName in settingsFlattened) {
        if (Object.hasOwnProperty.call(settingsFlattened, settingName)) {
            const setting = settingsFlattened[settingName];
            const selectID = settingName.replaceAll('.', '_')
            selectData.push({
                id: selectID,
                text: setting.name,
                setting: setting
            })
        }
    }

    $(document).ready(function() {
        $("#search-settings").select2({
                data: selectData,
                placeholder: '<?= __('Search setting by typing here...') ?>',
                templateResult: formatSettingSearchResult,
                templateSelection: formatSettingSearchSelection,
                matcher: settingMatcher,
                sorter: settingSorter,
            })
                .on('select2:select', function (e) {
                    const selected = e.params.data
                    const settingPath = selected.setting['setting-path']
                    const {tabName, IDtoFocus} = getTabAndSettingIDFromPath(settingPath)
                    showSetting(selected, tabName, IDtoFocus)
                    $("#search-settings").val(null).trigger('change.select2');
                })
    })

    function getTabAndSettingIDFromPath(settingPath) {
        let settingPathTokenized = settingPath.split('.')
        settingPathTokenized = settingPathTokenized.map((elem) => elem.replaceAll(/(\.|\W)/g, '_'))
        const tabName = settingPathTokenized[0]
        const IDtoFocus = 'sp-' + settingPathTokenized.slice(1).join('-')
        return {tabName: tabName, IDtoFocus: IDtoFocus}
    }

    function showSetting(selected, tabName, IDtoFocus) {
        const $navController = $('.settings-tabs').find('a.nav-link').filter(function() {
            return $(this).text() == tabName
        })
        if ($navController.length == 1) {
            $toFocus = $(`#${IDtoFocus}`).parent()
            if ($navController.hasClass('active')) {
                $toFocus[0].scrollIntoView()
                $toFocus.find(`input#${selected.id}, textarea#${selected.id}`).focus()
            } else {
                $navController.on('shown.bs.tab.after-selection', () => {
                    $toFocus[0].scrollIntoView()
                    $toFocus.find(`input#${selected.id}, textarea#${selected.id}`).focus()
                    $navController.off('shown.bs.tab.after-selection')
                }).tab('show')
            }
        }
    }

    function settingMatcher(params, data) {
        if (params.term == null || params.term.trim() === '') {
            return data;
        }
        if (data.text === undefined || data.setting === undefined) {
            return null;
        }
        let modifiedData = $.extend({}, data, true);
        const loweredTerms = params.term.trim().toLowerCase().split(' ')
        let matchNumber = 0
        for (let i = 0; i < loweredTerms.length; i++) {
            const loweredTerm = loweredTerms[i];
            const settingNameMatch = data.setting['true-name'].toLowerCase().indexOf(loweredTerm) > -1 || data.text.toLowerCase().indexOf(loweredTerm) > -1
            const settingGroupMatch = data.setting['setting-path'].toLowerCase().indexOf(loweredTerm) > -1
            const settingDescMatch = data.setting.description.toLowerCase().indexOf(loweredTerm) > -1
            if (settingNameMatch || settingGroupMatch || settingDescMatch) {
                matchNumber += 1
                modifiedData.matchPriority = (settingNameMatch ? 10 : 0) + (settingGroupMatch ? 5 : 0) + (settingDescMatch ? 1 : 0)
            }
        }
        if (matchNumber == loweredTerms.length && modifiedData.matchPriority > 0) {
            return modifiedData;
        }
        return null;
    }

    function settingSorter(data) {
        let sortedData = data.slice(0)
        sortedData = sortedData.sort((a, b) => {
            return a.matchPriority == b.matchPriority ? 0 : (b.matchPriority - a.matchPriority)
        })
        return sortedData;
    }

    function formatSettingSearchResult(state) {
        if (!state.id) {
            return state.text;
        }
        const $state = $('<div/>').append(
            $('<div/>').addClass('d-flex justify-content-between')
                .append(
                    $('<span/>').addClass('fw-bold').text(state.text),
                    $('<span/>').addClass('fw-light').text(state.setting['setting-path'].replaceAll('.', ' ▸ '))
                ),
            $('<div/>').addClass('font-italic fw-light ms-3').text(state.setting['description'])
        )
        return $state
    }
    
    function formatSettingSearchSelection(state) {
        return state.text
    }
</script>

<style>
    .select2-container {
        max-width: 100%;
        min-width: 100%;
    }
</style>