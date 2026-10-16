<?php
    $selectAllCheckbox = false;
    echo '<thead class="checkbox-index">';
    foreach ($fields as $k => $header) {
        if (!isset($header['requirement']) || $header['requirement']) {
            $header_data = '';
            // `header_html`: a heading drawn as markup (icons, a control), used as given.
            if (isset($header['header_html'])) {
                $header['name'] = $header['header_html'];
            } elseif (!empty($header['icon'])) {
                $header['name'] = sprintf(
                    '<i class="fas fa-%s"></i> %s',
                    h($header['icon']),
                    empty($header['name']) ? '' : h($header['name'])
                );
            } else {
                if (!empty($header['name'])) {
                    $header['name'] = h($header['name']);
                }
            }
            if (!empty($header['sort'])) {
                if (!empty($header['name'])) {
                    $header_data = $paginator->sort(
                        $header['sort'],
                        '<span class="sortable-header">' . $header['name'] . '<i class="sort-icon"></i></span>',
                        ['escape' => false]
                    );
                } else {
                    $header_data = $paginator->sort($header['sort']);
                }
            } elseif (!empty($header['client_sort'])) {
                /*
                 * `sort` above is Paginator's: it builds a link carrying
                 * ?sort=&direction= and reloads. A panel that pages
                 * client-side over rows it already holds cannot use that
                 * — the request would go somewhere with no idea what the
                 * fragment was showing. This renders the same affordance
                 * as a button naming its column, for a script on the page
                 * to act on, and reuses `sortable-header`/`sort-icon` so
                 * it looks like every other sortable heading in MISP.
                 *
                 * Guarded and new, so no existing caller of this element
                 * reaches it: none passes `client_sort`.
                 */
                $header_data = sprintf(
                    '<button type="button" class="vp-th-sort"'
                        . ' data-vp-sort-col="%s">'
                        . '<span class="sortable-header">%s'
                        . '<i class="sort-icon"></i></span></button>',
                    h($header['client_sort']),
                    empty($header['name']) ? '' : $header['name']
                );
            } else {
                if (!empty($header['element']) && in_array($header['element'], ['selector', 'checkbox'])) {
                    $selectAllCheckbox = true;
                    $header_data = sprintf(
                        '<input id="select_all" class="%s ms-1" type="checkbox" %s>',
                        empty($header['select_all_class']) ? 'select_all' : $header['select_all_class'],
                        empty($header['select_all_function']) ? 'onclick="toggleAllAttributeCheckboxes(this);"' : 'onclick="' . $header['select_all_function'] . '"'
                    );
                } else {
                    $header_data = $header['name'];
                }
            }
            $classes = [];
            if (!empty($header['sort'])) {
                $classes[] = 'pagination_link';
            }
            /*
             * `class` already lands on the <td> via row.ctp, and without a
             * counterpart here a caller can style a column's cells but not
             * its header — which is how a hidden column ends up with a
             * visible heading. A separate key rather than reusing `class`:
             * indexes pass `'class' => 'short'` for a cell width they do
             * not mean to impose on the heading too.
             *
             * `header_class` is the name two health-diagnostics tables
             * already use for this, though they render through the legacy
             * index table and never reach here — so no existing caller of
             * this element passes it, and every one of them renders
             * unchanged.
             */
            if (!empty($header['header_class'])) {
                $classes[] = $header['header_class'];
            }
            if (!empty($header['rotate_header'])) {
                $classes[] = 'rotate';
                $header_data = "<div><span>$header_data</span></div>";
            }

            if (!empty($header['actions'])) {
                $header_data = "<div class='me-2'><span>$header_data</span></div>";
            }

            echo sprintf(
                '<th%s%s>%s</th>',
                !empty($classes) ? ' class="' . implode(' ', $classes) .'"' : '',
                !empty($header['header_title']) ? ' title="' . h($header['header_title']) . '"' : '',
                $header_data
            );
        }
    }
    echo '</thead>';
?>