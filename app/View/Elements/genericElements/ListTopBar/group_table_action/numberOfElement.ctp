<?php
$numberOfElementSelectSeed = 'seed-' . mt_rand();
?>

<label class="dropdown-item d-flex align-items-center cursor-pointer" href="#" for="<?= $numberOfElementSelectSeed ?>">
    <span class="fw-bold">#</span>
    <span class="ms-2"><?= __('Show') ?></span>
    <select id="<?= $numberOfElementSelectSeed ?>" class="select-number-of-element form-select ms-auto" style="width: 5em;">
        <option value="20" <?= $numberOfElement == 20 ? 'selected' : '' ?>><?= __('20') ?></option>
        <option value="50" <?= $numberOfElement == 50 ? 'selected' : '' ?>><?= __('50') ?></option>
        <option value="100" <?= $numberOfElement == 100 ? 'selected' : '' ?>><?= __('100') ?></option>
        <option value="200" <?= $numberOfElement == 200 ? 'selected' : '' ?>><?= __('200') ?></option>
    </select>
</label>

<script>
    (function() {
        const debouncedNumberElementSaver = debounce(mergeAndSaveSettingsWithReload, 2000)

        $('#<?= $numberOfElementSelectSeed ?>').change(function() {
            const $dropdownMenu = $(this).closest('.dropdown')
            const tableRandomValue = $dropdownMenu.attr('data-table-random-value')
            const $container = $dropdownMenu.closest('div[id^="table-container-"]')
            const $table = $container.find(`table[data-table-random-value="${tableRandomValue}"]`)
            const table_setting_id = $dropdownMenu.data('table_setting_id');
            let newTableSettings = {}
            newTableSettings[table_setting_id] = {
                'number_of_element': $(this).val()
            }
            debouncedNumberElementSaver(table_setting_id, newTableSettings, $table)
        })

        $(document).ready(function() {
            const $select = $('#<?= $numberOfElementSelectSeed ?>')
            const $dropdownMenu = $select.closest('.dropdown')
            const tableRandomValue = $dropdownMenu.attr('data-table-random-value')
            const $container = $dropdownMenu.closest('div[id^="table-container-"]')
            const $table = $container.find(`table[data-table-random-value="${tableRandomValue}"]`)
            registerDebouncedFunction($container, debouncedNumberElementSaver)
        })
    })()
</script>