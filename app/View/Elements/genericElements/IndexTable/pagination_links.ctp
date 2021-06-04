<?php
    echo sprintf(
        '<div class="pagination"><ul>%s%s%s%s%s</ul></div>',
        $this->Paginator->first(
            '&laquo; ' . __('first'),
            ['tag' => 'li', 'escape' => false],
            null,
            ['tag' => 'li', 'class' => 'pagination_link first disabled', 'escape' => false, 'disabledTag' => 'span']
        ),
        $this->Paginator->prev(
            '&laquo; ' . __('previous'),
            ['tag' => 'li', 'escape' => false],
            null,
            ['tag' => 'li', 'class' => 'pagination_link prev disabled', 'escape' => false, 'disabledTag' => 'span']
        ),
        $this->Paginator->numbers(
            [
                'modulus' => 6,
                'separator' => '',
                'tag' => 'li',
                'currentClass' => 'active',
                'currentTag' => 'span',
                'class' => 'pagination_link'
            ]
        ),
        $this->Paginator->next(
            __('next') . ' &raquo;',
            ['tag' => 'li', 'escape' => false],
            null,
            ['tag' => 'li', 'class' => 'pagination_link next disabled', 'escape' => false, 'disabledTag' => 'span']
        ),
        $this->Paginator->last(
            __('last') . ' &raquo;',
            ['tag' => 'li', 'escape' => false],
            null,
            ['tag' => 'li', 'class' => 'pagination_link last disabled', 'escape' => false, 'disabledTag' => 'span']
        )
    );
