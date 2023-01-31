<?php
    /*
     *  Run a quick filter against the current API endpoint
     *  Result is passed via URL parameters, by default using the searchall key
     *  Valid parameters:
     *  - data: data-* fields
     *  - searchKey: data-search-key, specifying the key to be used (defaults to searchall)
     *  - fa-icon: an icon to use for the lookup $button
     *  - buttong: Text to use for the lookup button
     *  - cancel: Button for quickly removing the filters
     *  - placeholder: optional placeholder for the text field
     *  - id: element ID for the input field - defaults to quickFilterField
     */
    if (!isset($data['requirement']) || $data['requirement']) {
        if (!empty($data['quickFilter'])) {
            $quickFilter = $data['quickFilter'];
        }
        if (!empty($quickFilterForMetaField['enabled'])) {
            $quickFilter[] = [
                'MetaFields.value' => !empty($quickFilterForMetaField['wildcard_search'])
            ];
        }
        $filterEffective = !empty($quickFilter); // No filters will be picked up, thus rendering the filtering useless
        $filteringButton = '';
        if (!empty($data['allowFilering'])) {
            $activeFilters = !empty($activeFilters) ? $activeFilters : [];
            $numberActiveFilters = count($activeFilters);
            if (!empty($activeFilters['filteringMetaFields'])) {
                $numberActiveFilters += count($activeFilters['filteringMetaFields']) - 1;
            }
            $buttonConfig = [
                'icon' => 'filter',
                'variant' => $numberActiveFilters > 0 ? 'warning' : 'primary',
                'params' => [
                    'title' => __('Filter index'),
                    'id' => sprintf('toggleFilterButton-%s', h($tableRandomValue))
                ]
            ];
            if (count($activeFilters) > 0) {
                $buttonConfig['badge'] = [
                    'variant' => 'light',
                    'text' => $numberActiveFilters,
                    'title' => __n('There is {0} active filter', 'There are {0} active filters', $numberActiveFilters, $numberActiveFilters)
                ];
            }
            $filteringButton = $this->Bootstrap->button($buttonConfig);
        }
        $button = empty($data['button']) && empty($data['fa-icon']) ? '' : sprintf(
            '<button class="btn btn-primary" %s id="quickFilterButton-%s" %s>%s%s</button>%s',
            empty($data['data']) ? '' : h($data['data']),
            h($tableRandomValue),
            $filterEffective ? '' : 'disabled="disabled"',
            empty($data['fa-icon']) ? '' : sprintf('<i class="fa fa-%s"></i>', h($data['fa-icon'])),
            empty($data['button']) ? '' : h($data['button']),
            $filteringButton
        );
        if (!empty($data['cancel'])) {
            $button .= $this->element('/genericElements/ListTopBar/element_simple', array('data' => $data['cancel']));
        }
        $input = sprintf(
            '<input id="quickFilterField-%s" type="text" class="form-control" placeholder="%s" aria-label="%s" style="padding: 2px 6px;" id="%s" data-searchkey="%s" value="%s" %s>',
            h($tableRandomValue),
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['id']) ? 'quickFilterField' : h($data['id']),
            empty($data['searchKey']) ? 'searchall' : h($data['searchKey']),
            empty($data['value']) ? (!empty($quickFilterValue) ? h($quickFilterValue) : '') : h($data['value']),
            $filterEffective ? '' : 'disabled="disabled"'
        );
        echo sprintf(
            '<div class="input-group %s" data-table-random-value="%s" style="margin-left: auto;">%s%s</div>',
            $filterEffective ? '' : 'd-none',
            h($tableRandomValue),
            $input,
            $button
        );
    }
?>
<script type="text/javascript">
    $(document).ready(function() {
        var controller = '<?= $this->request->getParam('controller') ?>';
        var action = '<?= $this->request->getParam('action') ?>';
        var additionalUrlParams = '';
        var quickFilter = <?= json_encode(!empty($quickFilter) ? $quickFilter : []) ?>;
        var activeFilters = <?= json_encode(!empty($activeFilters) ? $activeFilters : []) ?>;
        <?php
            if (!empty($data['additionalUrlParams'])) {
                echo sprintf(
                    'additionalUrlParams = \'/%s\';',
                    h($data['additionalUrlParams'])
                );
            }
        ?>
        var randomValue = '<?= h($tableRandomValue) ?>';
        new bootstrap.Popover(`#quickFilterField-${randomValue}`, {
            title: '<?= __('Searcheable fields') ?>',
            content: function() { return buildPopoverQuickFilterBody(quickFilter) },
            placement: 'left',
            html: true,
            sanitize: false,
            trigger: 'manual',
        })
        $(`#quickFilterButton-${randomValue}`).click((e) => {
            doFilter($(e.target))
        });
        $(`#quickFilterField-${randomValue}`).on('keypress', (e) => {
            if (e.which === 13) {
                const $button = $(`#quickFilterButton-${randomValue}`)
                doFilter($button)
            }
        }).on('focus', (e) => {
            bootstrap.Popover.getInstance(`#quickFilterField-${randomValue}`).show()
        }).on('focusout', (e) => {
            bootstrap.Popover.getInstance(`#quickFilterField-${randomValue}`).hide()
        });

        $(`#toggleFilterButton-${randomValue}`)
            .data('activeFilters', activeFilters)
            .click(function() {
                const url = `/${controller}/filtering`
                const reloadUrl = `/${controller}/index${additionalUrlParams}`
                openFilteringModal(this, url, reloadUrl, $(`#index-table-${randomValue}`));
            })

        function doFilter($button) {
            bootstrap.Popover.getInstance(`#quickFilterField-${randomValue}`).hide()
            const encodedFilters = encodeURIComponent($(`#quickFilterField-${randomValue}`).val())
            const url = `/${controller}/${action}${additionalUrlParams}?quickFilter=${encodedFilters}`
            UI.reload(url, $(`#table-container-${randomValue}`), $(`#table-container-${randomValue} table.table`), [{
                node: $button,
                config: {}
            }])
        }

        function buildPopoverQuickFilterBody(quickFilter) {
            let tableData = []
            quickFilter.forEach(field => {
                let fieldName, searchContain
                if (typeof field === 'object') {
                    fieldName = Object.keys(field)[0];
                    searchContain = field[fieldName]
                } else {
                    fieldName = field
                    searchContain = false
                }
                $searchType = $('<span/>')
                    .text(searchContain ? '<?= __('Contain') ?>' : '<?= __('Exact match') ?>')
                    .attr('title', searchContain ? '<?= __('The search value can be used as a substring with the wildcard operator `%`') ?>' : '<?= __('The search value must strictly match') ?>')
                    .attr('style', 'cursor: help;')
                tableData.push([fieldName, $searchType])
            });
            tableData.sort((a, b) => a[0] < b[0] ? -1 : 1)
            $table = HtmlHelper.table(
                ['<?= __('Field name') ?>', '<?= __('Search type') ?>'],
                tableData,
                {
                    small: true,
                    tableClass: ['mb-0'],
                    caption: '<?= __('All these fields will be searched simultaneously') ?>'
                }
            )
            return $table[0].outerHTML
        }

        function openFilteringModal(clicked, url, reloadUrl, tableId) {
            const modalPromise = UI.submissionModalForIndex(url, reloadUrl, tableId)
            UI.overlayUntilResolve(clicked, modalPromise)
        }
    });
</script>
