<?php
$urlOptions = array_merge($this->request->params['pass'], $this->request->params['named']);
$urlOptions['controller'] = $this->params['controller'];
$urlOptions['action'] = $this->params['action'];
if (isset($urlOptions['page'])) {
    unset($urlOptions['page']);
}
$url = Router::url($urlOptions);
    $currentPage = $this->Paginator->param('page');
    $prev = sprintf(
        '<li class="page-item %s"><a class="page-link" href="%s" tabindex="-1">%s</a></li>',
        $this->Paginator->hasPrev() ? '' : 'disabled',
        $url . '/page:' . $this->Paginator->param('page') - 1,
        __('Previous')
    );
    $next = sprintf(
        '<li class="page-item %s"><a class="page-link" href="%s" tabindex="-1">%s</a></li>',
        $this->Paginator->hasNext() ? '' : 'disabled',
        $url . '/page:' . $this->Paginator->param('page') + 1,
        __('Next')
    );
    $numbers = [-2, -1, 0, 1, 2];
    $numberString = '';
    foreach ($numbers as $number) {
        $page = $currentPage + $number;
        if ($page < 1 || $page > $this->Paginator->param('count')) {
            continue;
        }
        $numberString .= sprintf(
            '<li class="page-item %s"><a class="page-link" href="%s" tabindex="-1">%s</a></li>',
            $page == $currentPage ? 'active' : '',
            $url . '/page:' . $page,
            $page
        );
    }

    echo sprintf(
        '<div class="pagination"><ul class="pagination">%s%s%s</ul></div>',
        $prev,
        $numberString,
        $next
    );
