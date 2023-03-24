<?php

namespace App\View\Helper\BootstrapElements;

use App\View\Helper\BootstrapGeneric;
use App\View\Helper\BootstrapHelper;

/**
 * # Options
 * - dropdown-class: Class for the dropdown
 * - alignment: How should the dropdown be aligned. Valid: "start", "end"
 * - direction: Position where the dropdown will be displayed Valid: "start", "end", "up", "down"
 * - button: Configuration for the dropdown button to be passed to BootstrapElements\BootstrapButton
 * - submenu_alignment: Alignment of the child dropdown will be displayed Valid: "start", "end", "up", "down"
 * - submenu_direction: Position where the child dropdown will be displayed Valid: "start", "end", "up", "down"
 * - attrs: Additional HTML attributes to be applied on the dropdown container
 * - menu: Entries making the dropdown menu. Accept the following options:
 *      - text: Text of the entry
 *      - html: HTML of the entry
 *      - icon: Icon displayed before the text
 *      - badge: Badge displayed after the text. Accepts BootstrapElements\BootstrapBadge
 *      - header: Is this item a list header
 *      - keepOpen: Keep the dropdown open if this entry is clicked
 *      - sup: Additional text to be added as a <sup> element
 *      - attrs: Additional HTML attributes to be applied on the entry
 * 
 * # Usage:
 * $this->Bootstrap->dropdownMenu([
 *     'dropdown-class' => 'ms-1',
 *     'alignment' => 'end',
 *     'direction' => 'down',
 *     'button' => [
 *         'icon' => 'sliders-h',
 *         'variant' => 'primary',
 *     ],
 *     'submenu_alignment' => 'end',
 *     'submenu_direction' => 'end',
 *     'attrs' => [],
 *     'menu' => [
 *         [
 *             'text' => __('Eye'),
 *             'icon' => 'eye-slash',
 *             'keepOpen' => true,
 *             'menu' => [
 *                 ['header' => true, 'text' => 'nested menu'],
 *                 ['text' => 'item 1'],
 *                 ['text' => 'item 2', 'sup' => 'v1'],
 *             ],
 *         ],
 *         [
 *             'html' => '<i class="p-3">html item</i>',
 *         ],
 *     ]
 * ]);
 */

class BootstrapDropdownMenu extends BootstrapGeneric
{
    private $defaultOptions = [
        'dropdown-class' => [],
        'alignment' => 'start',
        'direction' => 'end',
        'button' => [],
        'menu' => [],
        'submenu_direction' => 'end',
        'submenu_classes' => [],
        'attrs' => [],
    ];

    function __construct(array $options, BootstrapHelper $btHelper)
    {
        $this->allowedOptionValues = [
            'direction' => ['start', 'end', 'up', 'down'],
            'alignment' => ['start', 'end'],
            'submenu_direction' => ['start', 'end', 'up', 'down'],
        ];
        $this->processOptions($options);
        $this->menu = $this->options['menu'];
        $this->btHelper = $btHelper;
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['dropdown-class'] = $this->convertToArrayIfNeeded($this->options['dropdown-class']);
        $this->checkOptionValidity();
    }

    public function dropdownMenu(): string
    {
        return $this->fullDropdown();
    }

    public function fullDropdown(): string
    {
        return $this->genDropdownWrapper($this->genDropdownToggleButton(), $this->genDropdownMenu($this->menu));
    }

    public function genDropdownWrapper(string $toggle = '', string $menu = '', $direction = null, $classes = null): string
    {
        $classes = !is_null($classes) ? $classes :  $this->options['dropdown-class'];
        $direction = !is_null($direction) ? $direction : $this->options['direction'];
        $content = $toggle . $menu;
        $html = $this->node('div', array_merge(
            $this->options['attrs'],
            [
                'class' => array_merge(
                    $classes,
                    [
                        'dropdown',
                        "drop{$direction}"
                    ]
                )
            ]
        ), $content);
        return $html;
    }

    public function genDropdownToggleButton(): string
    {
        $defaultOptions = [
            'class' => ['dropdown-toggle'],
            'attrs' => [
                'data-bs-toggle' => 'dropdown',
                'aria-expanded' => 'false',
            ]
        ];
        $options = array_merge_recursive($this->options['button'], $defaultOptions);
        return $this->btHelper->button($options);
    }

    private function genDropdownMenu(array $entries, $alignment = null): string
    {
        $alignment = !is_null($alignment) ? $alignment : $this->options['alignment'];
        $html = $this->node('div', [
            'class' => ['dropdown-menu', "dropdown-menu-{$alignment}"],
        ], $this->genEntries($entries));
        return $html;
    }

    private function genEntries(array $entries): string
    {
        $html = '';
        foreach ($entries as $entry) {
            $link = $this->genEntry($entry);
            if (!empty($entry['menu'])) {
                $html .= $this->genDropdownWrapper($link, $this->genDropdownMenu($entry['menu']), $this->options['submenu_direction'], $this->options['submenu_classes']);
            } else {
                $html .= $link;
            }
        }
        return $html;
    }

    private function genEntry(array $entry): string
    {
        if (!empty($entry['html'])) {
            return $entry['html'];
        }
        $classes = [];
        $icon = '';
        if (!empty($entry['icon'])) {
            $icon = $this->btHelper->icon($entry['icon'], ['class' => 'me-2']);
        }
        $badge = '';
        if (!empty($entry['badge'])) {
            $bsBadge = new BootstrapBadge(array_merge(
                ['class' => ['ms-auto']],
                $entry['badge']
            ));
            $badge = $bsBadge->badge();
        }

        if (!empty($entry['header'])) {
            return $this->node('h6', [
                'class' => ['dropdown-header',],
            ], $icon . h($entry['text']) . $badge);
        }

        $classes = ['dropdown-item'];
        if (!empty($entry['class'])) {
            if (!is_array($entry['class'])) {
                $entry['class'] = [$entry['class']];
            }
            $classes = array_merge($classes, $entry['class']);
        }
        $params = $entry['attrs'] ?? [];
        $params['href'] = '#';

        if (!empty($entry['menu'])) {
            $classes[] = 'dropdown-toggle';
            $classes[] = 'd-flex align-items-center';
            $params['data-bs-toggle'] = 'dropdown';
            $params['aria-haspopup'] = 'true';
            $params['aria-expanded'] = 'false';
            if (!empty($entry['keepOpen'])) {
                $classes[] = 'open-form';
            }
            $params['data-open-form-id'] = mt_rand();
        }

        $labelContent = sprintf(
            '%s%s',
            h($entry['text']),
            !empty($entry['sup']) ? $this->node('sup', ['class' => 'ms-1 text-muted'], $entry['sup']) : ''
        );
        $label = $this->node('span', ['class' => 'mx-1'], $labelContent);
        $content = $icon . $label . $badge;

        return $this->node('a', array_merge([
            'class' => $classes,
        ], $params), $content);
    }
}
