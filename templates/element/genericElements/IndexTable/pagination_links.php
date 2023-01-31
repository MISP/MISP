<?php
    echo sprintf(
        '<nav aria-label="%s"><div class="pagination"><ul class="pagination">%s%s%s</ul></div></nav>',
        __(''),
        $this->Paginator->prev(__('Previous')),
        $this->Paginator->numbers(['first' => 1, 'last' => 1]),
        $this->Paginator->next(__('Next'))
    );
