<?php
$compactDisplayInputSeed = 'seed-' . mt_rand();
?>

<label class="dropdown-item d-flex align-items-center cursor-pointer" href="#" for="<?= $compactDisplayInputSeed ?>">
    <span class="fa fa-text-height"></span>
    <span class="ms-2"><?= __('Compact display') ?></span>
    <input id="<?= $compactDisplayInputSeed ?>" type="checkbox" class="checkbox-compact-table form-check-input ms-auto" <?= $compactDisplay ? 'checked="checked"' : '' ?>>
</label>

<script>
    (function() {
        const debouncedCompactSaver = debounce(mergeAndSaveSettings, 2000)

        $('#<?= $compactDisplayInputSeed ?>').change(function() {
            const $dropdownMenu = $(this).closest('.dropdown')
            const tableRandomValue = $dropdownMenu.attr('data-table-random-value')
            const $container = $dropdownMenu.closest('div[id^="table-container-"]')
            const $table = $container.find(`table[data-table-random-value="${tableRandomValue}"]`)
            const table_setting_id = $dropdownMenu.data('table_setting_id');
            toggleCompactState(this.checked, $table)
            let newTableSettings = {}
            newTableSettings[table_setting_id] = {
                'compact_display': this.checked
            }
            debouncedCompactSaver(table_setting_id, newTableSettings)
        })

        function toggleCompactState(isCompact, $table) {
            if (isCompact) {
                $table.addClass('table-sm')
            } else {
                $table.removeClass('table-sm')
            }
        }

        $(document).ready(function() {
            const $checkbox = $('#<?= $compactDisplayInputSeed ?>')
            const $dropdownMenu = $checkbox.closest('.dropdown')
            const tableRandomValue = $dropdownMenu.attr('data-table-random-value')
            const $container = $dropdownMenu.closest('div[id^="table-container-"]')
            const $table = $container.find(`table[data-table-random-value="${tableRandomValue}"]`)
            toggleCompactState($checkbox[0].checked, $table)
            registerDebouncedFunction($container, debouncedCompactSaver)
        })
    })()
</script>