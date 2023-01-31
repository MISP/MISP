<?php
    $options = array(
        'update' => '#table-container-' . h($tableRandomValue),
        'evalScripts' => true
    );
    if (!empty($paginationOptions)) {
        $options = array_merge($options, $paginationOptions);
    }
    $onClick = sprintf(
        'onClick="executePagination(%s, %s);"',
        "'" . h($tableRandomValue) . "'",
        "'{{url}}'"

    );
    $this->Paginator->setTemplates(
        [
            'nextActive' => '<li class="page-item"><a class="page-link" href="#" ' . $onClick . '>{{text}}</a></li>',
            'nextDisabled' => '<li class="page-item disabled"><a class="page-link" href="#" tabindex="-1">{{text}}</a></li>',
            'prevActive' => '<li class="page-item"><a class="page-link" href="#" ' . $onClick . '>{{text}}</a></li>',
            'prevDisabled' => '<li class="page-item disabled"><a class="page-link" href="#" tabindex="-1">{{text}}</a></li>',
            'counterRange' => '{{start}} - {{end}} of {{count}}',
            'counterPages' => '{{page}} of {{pages}}',
            'first' => '<li class="first"><a href="#" ' . $onClick . '>{{text}}</a></li>',
            'last' => '<li class="last"><a href="#" ' . $onClick . '>{{text}}</a></li>',
            'number' => '<li class="page-item"><a class="page-link" href="#" ' . $onClick . '>{{text}}</a></li>',
            'current' => '<li class="page-item active"><a href="" class="page-link">{{text}}</a></li>',
            'ellipsis' => '<li class="page-item disabled"><a href="" class="page-link"><span class="ellipsis">&hellip;</span></a></li>',
            'sort' => '<a href="#" ' . $onClick . ' class="d-inline-flex align-items-center">{{text}}</a>',
            'sortAsc' => '<a href="#" ' . $onClick . ' class="d-inline-flex align-items-center">{{text}} <i class="fas fa-sort-up ms-1"></i></a>',
            'sortDesc' => '<a href="#" ' . $onClick . ' class="d-inline-flex align-items-center">{{text}} <i class="fas fa-sort-down ms-1"></i></a>',
            'sortAscLocked' => '<a class="asc locked" href="#" ' . $onClick . ' class="d-inline-flex align-items-center">{{text}}</a>',
            'sortDescLocked' => '<a class="desc locked" href="#" ' . $onClick . ' class="d-inline-flex align-items-center");">{{text}}</a>'
        ]
    );
    echo $this->Paginator->options($options);
?>
