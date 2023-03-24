<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a Bootstrap list group where items can be links or buttons
 * 
 * # Options for list container
 *  - class: A list of class
 *  - attrs: A list of additional HTML attributes
 * 
 * # Options for list items
 *  - href: Link location
 *  - text: Text content of the item
 *  - html: Html content of the item
 *  - class: A list of class
 *  - attrs: A list of additional HTML attributes
 *  - badge: Options to be passed to BootstrapElements\BootstrapBadge
 * 
 * Usage:
 *    $this->Bootstrap->listGroup(
 *        [
 *            [
 *                'text' => 'test',
 *                'badge' => [
 *                    'text' => 'test',
 *                    'variant' => 'warning'
 *                ],
 *                'attrs' => [
 *                    'data-test' => 'tes'
 *                ]
 *            ],
 *            [
 *                'html' => '<i>test2</i>',
 *            ],
 *        ],
 *        [
 *            'class' => 'container-class'
 *        ]
 *    );
 */
class BootstrapListGroup extends BootstrapGeneric
{
    private $defaultOptions = [
        'class' => [],
        'attrs' => [],
    ];

    private $defaultItemOptions = [
        'href' => '#',
        'text' => '',
        'html' => null,
        'badge' => '',
        'class' => [],
        'attrs' => [],
    ];

    private static $defaultClasses = ['list-group',];
    private static $defaultItemClasses = ['list-group-item', 'list-group-item-action', 'd-flex', 'align-items-start', 'justify-content-between'];

    function __construct(array $items, array $options, \App\View\BootstrapHelper $btHelper)
    {
        $this->items = $items;
        $this->processOptions($options);
        $this->btHelper = $btHelper;
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['class'] = $this->convertToArrayIfNeeded($this->options['class']);
    }

    public function listGroup()
    {
        return $this->genListGroup();
    }

    private function genListGroup()
    {
        $html = $this->nodeOpen('div',  array_merge([
            'class' => array_merge(self::$defaultClasses, $this->options['class']),
        ], $this->options['attrs']));
        foreach ($this->items as $item) {
            $html .= $this->genItem($item);
        }
        $html .= $this->nodeClose('div');
        return $html;
    }

    private function genItem(array $item): string
    {
        $item['class'] = !is_array($item['class']) ? [$item['class']] : $item['class'];
        $itemOptions = array_merge($this->defaultItemOptions, $item);
        $itemOptions['class'] = array_merge(self::$defaultItemClasses, $itemOptions['class']);

        $html = $this->node('a',
            array_merge([
                'class' => array_merge(self::$defaultItemClasses, $itemOptions['class']),
                'href' => '#',
            ], $itemOptions['attrs']),
            [
                !is_null($itemOptions['html']) ? $this->node('div', ['class' => 'w-100'], $itemOptions['html']) : h($itemOptions['text']),
                $this->genBadge($itemOptions['badge'])
            ],
        );
        return $html;
    }

    private function genBadge(array $badge): string
    {
        if (empty($badge)) {
            return '';
        }
        return $this->btHelper->badge($badge);
    }
}