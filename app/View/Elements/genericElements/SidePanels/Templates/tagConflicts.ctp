<?php
    $conflictHtml = '';
    foreach ($warningTagConflicts as $taxonomy) {
        $conflictHtml .= sprintf(
            '<li><a href="%s/taxonomies/view/%s" title="%s">%s</a></li>',
            $baseurl,
            h($taxonomy['Taxonomy']['id']),
            h($taxonomy['Taxonomy']['description']),
            h($taxonomy['Taxonomy']['namespace'])
        );
        $conflictHtmlInternal = [];
        if ($taxonomy['Taxonomy']['exclusive']) {
            $conflictHtmlInternal[] = sprintf(
                '<li>%s</li>',
                sprintf(
                    ('%s is an exclusive taxonomy. Only one Tag of this taxonomy is allowed on an element.'),
                    sprintf('<strong>%s</strong>', h($taxonomy['Taxonomy']['namespace']))
                )
            );
        } else {
            foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
                $conflictHtmlInternal[] = sprintf(
                    '<li>%s</li>',
                    sprintf(
                        ('%s is an exclusive taxonomy predicate. Only one Tag of this predicate is allowed on an element'),
                        sprintf('<strong>%s</strong>', h($predicate['value']))
                    )
                );
            }
        }
        $conflictHtml .= sprintf(
            '<ul>%s</ul>',
            implode(PHP_EOL, $conflictHtmlInternal)
        );
    }

    echo sprintf(
        '<div class="warning_container"><h4 class="red">%s</h4>%s</div>',
        __('Warning: Taxonomy inconsistencies'),
        $conflictHtml
    );
