<?php

namespace App\View\Helper\BootstrapElements;

use Cake\Utility\Security;

use App\View\Helper\BootstrapGeneric;

/**
 * Creates a bootstrap panel with navigation component.
 * 
 * # Options:
 * - fill-header: Should the navigation header takes up all the space available
 * - justify-header: Allow to specify how the naviation component should be justified. Accepts: false (no justify), 'start', 'end', 'center';
 * - pills: Should the navigation element be pills
 * - card: Should the content and navigation elements be wrapped in a Bootstrap card component
 * - header-variant, body-variant: The variant that the card's header and body should have. Ignore if $card is not set
 * - body-class, nav-class, nav-class-item, content-class: Additional classes to be added to the nav, body, navigation items or content
 * - vertical: Should the navigation component be placed vertically next to the content. Best used with the `pills` option enabled.
 * - vertical-size: Controls the horizontal size of the vertical header. Must be between [1, 11]
 * - vertical-position: Controls the position of the header. Accepts 'start and 'end'
 * - horizontal-position: Controls the position of the header. Accepts 'top and 'bottom'
 * - data: The data used to generate the tabs. Must have a `navs` and `content` key. See the "# Data" section
 * 
 * # Data
 * - navs: The data for the navigation items. Supported options:
 *      - id: The ID of the nav. Auto-generated if left empty
 *      - active: Should the tab be active
 *      - disabled: Should the tab be disabled
 *      - text: The text content of the tab
 *      - html: The HTML content of the tab
 * 
 * - content: The HTML content for each tabs
 * 
 * # Usage:
 * ## Simple formatted tabs using the card option
 *  echo $this->Bootstrap->tabs([
 *     'horizontal-position' => 'top',
 *     'header-variant' => 'danger',
 *     'card' => true,
 *     'data' => [
 *         'navs' => [
 *             ['text' => 'nav 1'],
 *             ['html' => '<b>nav 2</b>', 'active' => true],
 *         ],
 *         'content' => [
 *             '<i>content 1</i>',
 *             'content 2',
 *         ]
 *     ]
 * ]);
 * 
 * ## Simple formatted tabs using the card option and vertical options
 *  echo $this->Bootstrap->tabs([
 *     'pills' => true,
 *     'vertical' => true,
 *     'vertical-position' => 'start',
 *     'card' => true,
 *     'data' => [
 *         'navs' => [
 *             ['text' => 'nav 1'],
 *             ['html' => '<b>nav 2</b>', 'disabled' => true],
 *         ],
 *         'content' => [
 *             '<i>content 1</i>',
 *             'content 2',
 *         ]
 *     ]
 * ]);
 */
class BootstrapTabs extends BootstrapGeneric
{
    private $defaultOptions = [
        'id' => '',
        'fill-header' => false,
        'justify-header' => false,
        'pills' => false,
        'vertical' => false,
        'vertical-size' => 3,
        'vertical-position' => 'start',
        'horizontal-position' => 'top',
        'card' => false,
        'header-variant' => '',
        'body-variant' => '',
        'body-class' => [],
        'nav-class' => [],
        'nav-item-class' => [],
        'content-class' => [],
        'data' => [
            'navs' => [],
            'content' => [],
        ],
    ];
    private $bsClasses = null;

    function __construct(array $options)
    {
        $this->allowedOptionValues = [
            'justify-header' => [false, 'center', 'end', 'start'],
            'vertical-position' => ['start', 'end'],
            'horizontal-position' => ['top', 'bottom'],
            'body-variant' => array_merge(BootstrapGeneric::$variants, ['']),
            'header-variant' => array_merge(BootstrapGeneric::$variants, ['']),
        ];
        $this->processOptions($options);
    }

    public function tabs(): string
    {
        return $this->genTabs();
    }

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->data = $this->options['data'];
        $this->checkOptionValidity();
        if (empty($this->data['navs'])) {
            throw new InvalidArgumentException(__('No navigation data provided'));
        }
        $this->bsClasses = [
            'nav' => [],
            'nav-item' => $this->options['nav-item-class'],
        ];

        if (!empty($this->options['justify-header'])) {
            $this->bsClasses['nav'][] = 'justify-content-' . $this->options['justify-header'];
        }

        if ($this->options['vertical'] && !isset($options['pills']) && !isset($options['card'])) {
            $this->options['pills'] = true;
            $this->options['card'] = true;
        }

        if ($this->options['pills']) {
            $this->bsClasses['nav'][] = 'nav-pills';
            if ($this->options['vertical']) {
                $this->bsClasses['nav'][] = 'flex-column';
            }
            if ($this->options['card']) {
                $this->bsClasses['nav'][] = 'card-header-pills';
            }
        } else {
            $this->bsClasses['nav'][] = 'nav-tabs';
            if ($this->options['card']) {
                $this->bsClasses['nav'][] = 'card-header-tabs';
            }
        }

        if ($this->options['fill-header']) {
            $this->bsClasses['nav'][] = 'nav-fill';
        }
        if ($this->options['justify-header']) {
            $this->bsClasses['nav'][] = 'nav-justify';
        }

        $activeTab = array_key_first($this->data['navs']);
        foreach ($this->data['navs'] as $i => $nav) {
            if (!is_array($nav)) {
                $this->data['navs'][$i] = ['text' => $nav];
            }
            if (!isset($this->data['navs'][$i]['id'])) {
                $this->data['navs'][$i]['id'] = 't-' . Security::randomString(8);
            }
            if (!empty($nav['active'])) {
                $activeTab = $i;
            }
        }
        $this->data['navs'][$activeTab]['active'] = true;

        if (!empty($this->options['vertical-size']) && $this->options['vertical-size'] != 'auto') {
            $this->options['vertical-size'] = ($this->options['vertical-size'] < 0 || $this->options['vertical-size'] > 11) ? 3 : $this->options['vertical-size'];
        }

        if (!is_array($this->options['nav-class'])) {
            $this->options['nav-class'] = [$this->options['nav-class']];
        }
        if (!is_array($this->options['content-class'])) {
            $this->options['content-class'] = [$this->options['content-class']];
        }
    }

    private function genTabs(): string
    {
        return $this->options['vertical'] ? $this->genVerticalTabs() : $this->genHorizontalTabs();
    }

    private function genHorizontalTabs(): string
    {
        if ($this->options['card']) {
            $cardOptions = [
                'bodyHTML' => $this->genContent(),
                'bodyVariant' => $this->options['body-variant'],
            ];
            if ($this->options['horizontal-position'] === 'bottom') {
                $cardOptions['footerHTML'] = $this->genNav();
                $cardOptions['footerVariant'] = $this->options['header-variant'];
                $cardOptions['headerVariant'] = $this->options['header-variant'];
            } else {
                $cardOptions['headerHTML'] = $this->genNav();
                $cardOptions['headerVariant'] = $this->options['header-variant'];
            }
            $bsCard = new BootstrapCard($cardOptions);
            return $bsCard->card();
        } else {
            return $this->genNav() . $this->genContent();
        }
    }

    private function genVerticalTabs(): string
    {
        $header = $this->node('div', ['class' => array_merge(
            [
                ($this->options['vertical-size'] != 'auto' ? 'col-' . $this->options['vertical-size'] : ''),
                ($this->options['card'] ? 'card-header border-end' : '')
            ],
            [
                "bg-{$this->options['header-variant']}",
            ]
        )], $this->genNav());
        $content = $this->node('div', ['class' => array_merge(
            [
                ($this->options['vertical-size'] != 'auto' ? 'col-' . (12 - $this->options['vertical-size']) : ''),
                ($this->options['card'] ? 'card-body2' : '')
            ],
            [
                "bg-{$this->options['body-variant']}",
            ]
        )], $this->genContent());

        $containerContent = $this->options['vertical-position'] === 'start' ? [$header, $content] : [$content, $header];
        $container = $this->node('div', ['class' => array_merge(
            [
                'row',
                ($this->options['card'] ? 'card flex-row' : ''),
                ($this->options['vertical-size'] == 'auto' ? 'flex-nowrap' : '')
            ],
            [
            ]
        )], $containerContent);
        return $container;
    }

    private function genNav(): string
    {
        $ulOptions = [
            'class' => array_merge(['nav'], $this->bsClasses['nav'], $this->options['nav-class']),
            'role' => 'tablist',
        ];
        if (!empty($this->options['id'])) {
            $ulOptions['id'] = $this->options['id'];
        }
        $html = $this->nodeOpen('ul', $ulOptions);
        foreach ($this->data['navs'] as $navItem) {
            $html .= $this->genNavItem($navItem);
        }
        $html .= $this->nodeClose('ul');
        return $html;
    }

    private function genNavItem(array $navItem): string
    {
        $html = $this->nodeOpen('li', [
            'class' => array_merge(['nav-item'], $this->bsClasses['nav-item'], $this->options['nav-item-class']),
            'role' => 'presentation',
        ]);
        $html .= $this->nodeOpen('a', [
            'class' => array_merge(
                ['nav-link'],
                [!empty($navItem['active']) ? 'active' : ''],
                [!empty($navItem['disabled']) ? 'disabled' : '']
            ),
            'data-bs-toggle' => $this->options['pills'] ? 'pill' : 'tab',
            'id' => $navItem['id'] . '-tab',
            'href' => '#' . $navItem['id'],
            'aria-controls' => $navItem['id'],
            'aria-selected' => !empty($navItem['active']),
            'role' => 'tab',
        ]);
        $html .= $navItem['html'] ?? h($navItem['text']);
        $html .= $this->nodeClose('a');
        $html .= $this->nodeClose('li');
        return $html;
    }

    private function genContent(): string
    {
        $html = $this->nodeOpen('div', [
            'class' => array_merge(['tab-content'], $this->options['content-class']),
        ]);
        foreach ($this->data['content'] as $i => $content) {
            $navItem = $this->data['navs'][$i];
            $html .= $this->genContentItem($navItem, $content);
        }
        $html .= $this->nodeClose('div');
        return $html;
    }

    private function genContentItem(array $navItem, string $content): string
    {
        return $this->node('div', [
            'class' => array_merge(['tab-pane', 'fade'], [!empty($navItem['active']) ? 'show active' : '']),
            'role' => 'tabpanel',
            'id' => $navItem['id'],
            'aria-labelledby' => $navItem['id'] . '-tab'
        ], $content);
    }
}
