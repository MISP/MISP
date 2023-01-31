<?php

/**
 * Bootstrap Tabs helper
 * Options:
 *  [style]
 *      - fill: Should the navigation items occupy all available space
 *      - justify: Should the navigation items be justified (accept: ['center', 'end'])
 *      - pills: Should the navigation items be pills
 *      - vertical: Should the navigation bar be placed on the left side of the content
 *      - vertical-size: Specify how many boostrap's `cols` should be used for the navigation (only used when `vertical` is true)
 *      - card: Should the navigation be placed in a bootstrap card
 *      - header-variant: The bootstrap variant to be used for the card header
 *      - body-variant: The bootstrap variant to be used for the card body
 *      - nav-class: additional class to add to the nav container
 *      - content-class: additional class to add to the content container
 *  [data]
 *      - data: contains the data for the tabs and content
 *      {
 *          'navs': [{nav-item}, {nav-item}, ...],
 *          'content': [{nav-content}, {nav-content}, ...]
 *      }
 * 
 * # Usage:
 *    echo $this->Bootstrap->Tabs([
 *       'pills' => true,
 *       'card' => true,
 *       'data' => [
 *           'navs' => [
 *               'tab1',
 *               ['text' => 'tab2', 'active' => true],
 *               ['html' => '<b>tab3</b>', 'disabled' => true],
 *           ],
 *           'content' => [
 *               'body1',
 *               '<i>body2</i>',
 *               '~body3~'
 *           ]
 *       ]
 *   ]);
 */

namespace App\View\Helper;

use Cake\View\Helper;
use Cake\Utility\Hash;
use Cake\Utility\Inflector;
use Cake\Utility\Security;
use InvalidArgumentException;

class BootstrapHelper extends Helper
{
    public $helpers = ['FontAwesome'];

    public function tabs($options)
    {
        $bsTabs = new BootstrapTabs($options);
        return $bsTabs->tabs();
    }

    public function alert($options)
    {
        $bsAlert = new BoostrapAlert($options);
        return $bsAlert->alert();
    }

    public function table($options, $data)
    {
        $bsTable = new BoostrapTable($options, $data, $this);
        return $bsTable->table();
    }

    public function listTable($options, $data)
    {
        $bsListTable = new BoostrapListTable($options, $data, $this);
        return $bsListTable->table();
    }

    public function button($options)
    {
        $bsButton = new BoostrapButton($options);
        return $bsButton->button();
    }

    public function icon($icon, $options = [])
    {
        $bsIcon = new BoostrapIcon($icon, $options);
        return $bsIcon->icon();
    }

    public function badge($options)
    {
        $bsBadge = new BoostrapBadge($options);
        return $bsBadge->badge();
    }

    public function modal($options)
    {
        $bsModal = new BoostrapModal($options);
        return $bsModal->modal();
    }

    public function card($options)
    {
        $bsCard = new BoostrapCard($options);
        return $bsCard->card();
    }

    public function progress($options)
    {
        $bsProgress = new BoostrapProgress($options);
        return $bsProgress->progress();
    }

    public function collapse($options, $content)
    {
        $bsCollapse = new BoostrapCollapse($options, $content, $this);
        return $bsCollapse->collapse();
    }

    public function accordion($options, $content)
    {
        $bsAccordion = new BoostrapAccordion($options, $content, $this);
        return $bsAccordion->accordion();
    }

    public function progressTimeline($options)
    {
        $bsProgressTimeline = new BoostrapProgressTimeline($options, $this);
        return $bsProgressTimeline->progressTimeline();
    }

    public function listGroup($options, $data)
    {
        $bsListGroup = new BootstrapListGroup($options, $data, $this);
        return $bsListGroup->listGroup();
    }

    public function genNode($node, $params = [], $content = '')
    {
        return BootstrapGeneric::genNode($node, $params, $content);
    }

    public function switch($options)
    {
        $bsSwitch = new BoostrapSwitch($options, $this);
        return $bsSwitch->switch();
    }

    public function notificationBubble($options)
    {
        $bsNotificationBubble = new BoostrapNotificationBuble($options, $this);
        return $bsNotificationBubble->notificationBubble();
    }

    public function dropdownMenu($options)
    {
        $bsDropdownMenu = new BoostrapDropdownMenu($options, $this);
        return $bsDropdownMenu->dropdownMenu();
    }
}

class BootstrapGeneric
{
    public static $variants = ['primary', 'secondary', 'success', 'danger', 'warning', 'info', 'light', 'dark', 'white', 'transparent'];
    public static $textClassByVariants = [
        'primary' => 'text-light',
        'secondary' => 'text-light',
        'success' => 'text-light',
        'danger' => 'text-light',
        'warning' => 'text-dark',
        'info' => 'text-light',
        'light' => 'text-dark',
        'dark' => 'text-light',
        'white' => 'text-dark',
        'transparent' => 'text-dark'
    ];
    protected $allowedOptionValues = [];
    protected $options = [];

    protected function checkOptionValidity()
    {
        foreach ($this->allowedOptionValues as $option => $values) {
            if (!isset($this->options[$option])) {
                throw new InvalidArgumentException(__('Option `{0}` should have a value', $option));
            }
            if (!in_array($this->options[$option], $values)) {
                throw new InvalidArgumentException(__('Option `{0}` is not a valid option for `{1}`. Accepted values: {2}', json_encode($this->options[$option]), $option, json_encode($values)));
            }
        }
    }

    public static function genNode($node, $params = [], $content = "")
    {
        return sprintf('<%s %s>%s</%s>', $node, BootstrapGeneric::genHTMLParams($params), $content, $node);
    }

    protected static function openNode($node, $params = [])
    {
        return sprintf('<%s %s>', $node, BootstrapGeneric::genHTMLParams($params));
    }

    protected static function closeNode($node)
    {
        return sprintf('</%s>', $node);
    }

    protected static function genHTMLParams($params)
    {
        $html = '';
        foreach ($params as $k => $v) {
            if (!empty($k) && (isset($v) && $v !== '')) {
                $html .= BootstrapGeneric::genHTMLParam($k, $v) . ' ';
            }
        }
        return $html;
    }

    protected static function genHTMLParam($paramName, $values)
    {
        if (!is_array($values)) {
            $values = [$values];
        }
        return sprintf('%s="%s"', $paramName, implode(' ', $values));
    }

    protected static function genericCloseButton($dismissTarget)
    {
        return BootstrapGeneric::genNode('button', [
            'type' => 'button',
            'class' => 'btn-close',
            'data-bs-dismiss' => $dismissTarget,
            'arial-label' => __('Close')
        ]);
    }

    protected static function getTextClassForVariant($variant)
    {
        return !empty(self::$textClassByVariants[$variant]) ? self::$textClassByVariants[$variant] : 'text-black';
    }
}

class BootstrapTabs extends BootstrapGeneric
{
    private $defaultOptions = [
        'fill' => false,
        'justify' => false,
        'pills' => false,
        'vertical' => false,
        'vertical-size' => 3,
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

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'justify' => [false, 'center', 'end'],
            'body-variant' => array_merge(BootstrapGeneric::$variants, ['']),
            'header-variant' => array_merge(BootstrapGeneric::$variants, ['']),
        ];
        $this->processOptions($options);
    }

    public function tabs()
    {
        return $this->genTabs();
    }

    private function processOptions($options)
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

        if (!empty($this->options['justify'])) {
            $this->bsClasses['nav'][] = 'justify-content-' . $this->options['justify'];
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

        if ($this->options['fill']) {
            $this->bsClasses['nav'][] = 'nav-fill';
        }
        if ($this->options['justify']) {
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
            $this->options['vertical-size'] = $this->options['vertical-size'] < 0 || $this->options['vertical-size'] > 11 ? 3 : $this->options['vertical-size'];
        }

        $this->options['header-text-variant'] = $this->options['header-variant'] == 'light' ? 'body' : 'white';
        $this->options['header-border-variant'] = $this->options['header-variant'] == 'light' ? '' : $this->options['header-variant'];
        $this->options['body-text-variant'] = $this->options['body-variant'] == '' ? 'body' : 'white';

        if (!is_array($this->options['nav-class'])) {
            $this->options['nav-class'] = [$this->options['nav-class']];
        }
        if (!is_array($this->options['content-class'])) {
            $this->options['content-class'] = [$this->options['content-class']];
        }
    }

    private function genTabs()
    {
        $html = '';
        if ($this->options['vertical']) {
            $html .= $this->genVerticalTabs();
        } else {
            $html .= $this->genHorizontalTabs();
        }
        return $html;
    }

    private function genHorizontalTabs()
    {
        $html = '';
        if ($this->options['card']) {
            $html .= $this->openNode('div', ['class' => array_merge(['card'], ["border-{$this->options['header-border-variant']}"])]);
            $html .= $this->openNode('div', ['class' => array_merge(['card-header'], ["bg-{$this->options['header-variant']}", "text-{$this->options['header-text-variant']}"])]);
        }
        $html .= $this->genNav();
        if ($this->options['card']) {
            $html .= $this->closeNode('div');
            $html .= $this->openNode('div', [
                'class' => array_merge(
                    ['card-body'],
                    $this->options['body-class'] ?? [],
                    ["bg-{$this->options['body-variant']}", "text-{$this->options['body-text-variant']}"]
                )
            ]);
        }
        $html .= $this->genContent();
        if ($this->options['card']) {
            $html .= $this->closeNode('div');
            $html .= $this->closeNode('div');
        }
        return $html;
    }

    private function genVerticalTabs()
    {
        $html = $this->openNode('div', ['class' => array_merge(
            [
                'row',
                ($this->options['card'] ? 'card flex-row' : ''),
                ($this->options['vertical-size'] == 'auto' ? 'flex-nowrap' : '')
            ],
            [
                "border-{$this->options['header-border-variant']}"
            ]
        )]);
        $html .= $this->openNode('div', ['class' => array_merge(
            [
                ($this->options['vertical-size'] != 'auto' ? 'col-' . $this->options['vertical-size'] : ''),
                ($this->options['card'] ? 'card-header border-end' : '')
            ],
            [
                "bg-{$this->options['header-variant']}",
                "text-{$this->options['header-text-variant']}",
                "border-{$this->options['header-border-variant']}"
            ]
        )]);
        $html .= $this->genNav();
        $html .= $this->closeNode('div');
        $html .= $this->openNode('div', ['class' => array_merge(
            [
                ($this->options['vertical-size'] != 'auto' ? 'col-' . (12 - $this->options['vertical-size']) : ''),
                ($this->options['card'] ? 'card-body2' : '')
            ],
            [
                "bg-{$this->options['body-variant']}",
                "text-{$this->options['body-text-variant']}"
            ]
        )]);
        $html .= $this->genContent();
        $html .= $this->closeNode('div');
        $html .= $this->closeNode('div');
        return $html;
    }

    private function genNav()
    {
        $html = $this->openNode('ul', [
            'class' => array_merge(['nav'], $this->bsClasses['nav'], $this->options['nav-class']),
            'role' => 'tablist',
        ]);
        foreach ($this->data['navs'] as $navItem) {
            $html .= $this->genNavItem($navItem);
        }
        $html .= $this->closeNode('ul');
        return $html;
    }

    private function genNavItem($navItem)
    {
        $html = $this->openNode('li', [
            'class' => array_merge(['nav-item'], $this->bsClasses['nav-item'], $this->options['nav-item-class']),
            'role' => 'presentation',
        ]);
        $html .= $this->openNode('a', [
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
        if (!empty($navItem['html'])) {
            $html .= $navItem['html'];
        } else {
            $html .= h($navItem['text']);
        }
        $html .= $this->closeNode('a');
        $html .= $this->closeNode('li');
        return $html;
    }

    private function genContent()
    {
        $html = $this->openNode('div', [
            'class' => array_merge(['tab-content'], $this->options['content-class']),
        ]);
        foreach ($this->data['content'] as $i => $content) {
            $navItem = $this->data['navs'][$i];
            $html .= $this->genContentItem($navItem, $content);
        }
        $html .= $this->closeNode('div');
        return $html;
    }

    private function genContentItem($navItem, $content)
    {
        return $this->genNode('div', [
            'class' => array_merge(['tab-pane', 'fade'], [!empty($navItem['active']) ? 'show active' : '']),
            'role' => 'tabpanel',
            'id' => $navItem['id'],
            'aria-labelledby' => $navItem['id'] . '-tab'
        ], $content);
    }
}

class BoostrapAlert extends BootstrapGeneric
{
    private $defaultOptions = [
        'text' => '',
        'html' => null,
        'dismissible' => true,
        'variant' => 'primary',
        'fade' => true
    ];

    private $bsClasses = null;

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function alert()
    {
        return $this->genAlert();
    }

    private function genAlert()
    {
        $html = $this->openNode('div', [
            'class' => [
                'alert',
                "alert-{$this->options['variant']}",
                $this->options['dismissible'] ? 'alert-dismissible' : '',
                $this->options['fade'] ? 'fade show' : '',
            ],
            'role' => "alert"
        ]);

        $html .= $this->genContent();
        $html .= $this->genCloseButton();
        $html .= $this->closeNode('div');
        return $html;
    }

    private function genCloseButton()
    {
        $html = '';
        if ($this->options['dismissible']) {
            $html .= $this->genericCloseButton('alert');
        }
        return $html;
    }

    private function genContent()
    {
        return !is_null($this->options['html']) ? $this->options['html'] : h($this->options['text']);
    }
}

class BoostrapTable extends BootstrapGeneric
{
    private $defaultOptions = [
        'striped' => true,
        'bordered' => true,
        'borderless' => false,
        'hover' => true,
        'small' => false,
        'variant' => '',
        'tableClass' => [],
        'headerClass' => [],
        'bodyClass' => [],
    ];

    private $bsClasses = null;

    function __construct($options, $data, $btHelper)
    {
        $this->allowedOptionValues = [
            'variant' => array_merge(BootstrapGeneric::$variants, [''])
        ];
        $this->processOptions($options);
        $this->fields = $data['fields'];
        $this->items = $data['items'];
        $this->caption = !empty($data['caption']) ? $data['caption'] : '';
        $this->btHelper = $btHelper;
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function table()
    {
        return $this->genTable();
    }

    private function genTable()
    {
        $html = $this->openNode('table', [
            'class' => [
                'table',
                "table-{$this->options['variant']}",
                $this->options['striped'] ? 'table-striped' : '',
                $this->options['bordered'] ? 'table-bordered' : '',
                $this->options['borderless'] ? 'table-borderless' : '',
                $this->options['hover'] ? 'table-hover' : '',
                $this->options['small'] ? 'table-sm' : '',
                !empty($this->options['variant']) ? "table-{$this->options['variant']}" : '',
                !empty($this->options['tableClass']) ? (is_array($this->options['tableClass']) ? implode(' ', $this->options['tableClass']) : $this->options['tableClass']) : ''
            ],
        ]);

        $html .= $this->genCaption();
        $html .= $this->genHeader();
        $html .= $this->genBody();

        $html .= $this->closeNode('table');
        return $html;
    }

    private function genHeader()
    {
        $head =  $this->openNode('thead', [
            'class' => [
                !empty($this->options['headerClass']) ? $this->options['headerClass'] : ''
            ],
        ]);
        $head .= $this->openNode('tr');
        foreach ($this->fields as $i => $field) {
            if (is_array($field)) {
                if (!empty($field['labelHtml'])) {
                    $label = $field['labelHtml'];
                } else {
                    $label = !empty($field['label']) ? $field['label'] : Inflector::humanize($field['key']);
                    $label = h($label);
                }
            } else {
                $label = Inflector::humanize($field);
                $label = h($label);
            }
            $head .= $this->genNode('th', [], $label);
        }
        $head .= $this->closeNode('tr');
        $head .= $this->closeNode('thead');
        return $head;
    }

    private function genBody()
    {
        $body =  $this->openNode('tbody', [
            'class' => [
                !empty($this->options['bodyClass']) ? (is_array($this->options['bodyClass']) ? implode(' ', $this->options['bodyClass']) : $this->options['bodyClass']) : ''
            ],
        ]);
        foreach ($this->items as $i => $row) {
            $body .= $this->genRow($row, $i);
        }
        $body .= $this->closeNode('tbody');
        return $body;
    }

    private function genRow($row, $rowIndex)
    {
        $html = $this->openNode('tr', [
            'class' => [
                !empty($row['_rowVariant']) ? "table-{$row['_rowVariant']}" : ''
            ]
        ]);
        if (array_keys($row) !== range(0, count($row) - 1)) { // associative array
            foreach ($this->fields as $i => $field) {
                if (is_array($field)) {
                    $key = $field['key'];
                } else {
                    $key = $field;
                }
                $cellValue = Hash::get($row, $key);
                $html .= $this->genCell($cellValue, $field, $row, $rowIndex);
            }
        } else { // indexed array
            foreach ($row as $i => $cellValue) {
                $html .= $this->genCell($cellValue, 'index', $row, $rowIndex);
            }
        }
        $html .= $this->closeNode('tr');
        return $html;
    }

    private function genCell($value, $field=[], $row=[], $rowIndex=0)
    {
        if (isset($field['formatter'])) {
            $cellContent = $field['formatter']($value, $row, $rowIndex);
        } else if (isset($field['element'])) {
            $cellContent = $this->btHelper->getView()->element($field['element'], [
                'data' => [$value],
                'field' => ['path' => '0']
            ]);
        } else {
            $cellContent = h($value);
        }
        return $this->genNode('td', [
            'class' => [
                !empty($row['_cellVariant']) ? "bg-{$row['_cellVariant']}" : ''
            ]
        ], $cellContent);
    }

    private function genCaption()
    {
        return !empty($this->caption) ? $this->genNode('caption', [], h($this->caption)) : '';
    }
}

class BoostrapListTable extends BootstrapGeneric
{
    private $defaultOptions = [
        'striped' => true,
        'bordered' => false,
        'borderless' => false,
        'hover' => true,
        'small' => false,
        'variant' => '',
        'tableClass' => [],
        'bodyClass' => [],
    ];

    private $bsClasses = null;

    function __construct($options, $data, $btHelper)
    {
        $this->allowedOptionValues = [
            'variant' => array_merge(BootstrapGeneric::$variants, [''])
        ];
        $this->processOptions($options);
        $this->fields = $data['fields'];
        $this->item = $data['item'];
        $this->caption = !empty($data['caption']) ? $data['caption'] : '';
        $this->btHelper = $btHelper;
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function table()
    {
        return $this->genTable();
    }

    private function genTable()
    {
        $html = $this->openNode('table', [
            'class' => [
                'table',
                "table-{$this->options['variant']}",
                $this->options['striped'] ? 'table-striped' : '',
                $this->options['bordered'] ? 'table-bordered' : '',
                $this->options['borderless'] ? 'table-borderless' : '',
                $this->options['hover'] ? 'table-hover' : '',
                $this->options['small'] ? 'table-sm' : '',
                !empty($this->options['variant']) ? "table-{$this->options['variant']}" : '',
                !empty($this->options['tableClass']) ? (is_array($this->options['tableClass']) ? implode(' ', $this->options['tableClass']) : $this->options['tableClass']) : ''
            ],
            'id' => $this->options['id'] ?? ''
        ]);

        $html .= $this->genCaption();
        $html .= $this->genBody();

        $html .= $this->closeNode('table');
        return $html;
    }

    private function genBody()
    {
        $body =  $this->openNode('tbody', [
            'class' => [
                !empty($this->options['bodyClass']) ? (is_array($this->options['bodyClass']) ? implode(' ', $this->options['bodyClass']) : $this->options['bodyClass']) : ''
            ],
        ]);
        foreach ($this->fields as $i => $field) {
            $body .= $this->genRow($field);
        }
        $body .= $this->closeNode('tbody');
        return $body;
    }

    private function genRow($field)
    {
        $rowValue = $this->genCell($field);
        $rowKey = $this->genNode('th', [
            'class' => [
                'col-4 col-sm-2'
            ],
            'scope' => 'row'
        ], h($field['key']));
        $row = $this->genNode('tr', [
            'class' => [
                'd-flex',
                !empty($field['_rowVariant']) ? "table-{$field['_rowVariant']}" : ''
            ]
        ], implode('', [$rowKey, $rowValue]));
        return $row;
    }

    private function genCell($field = [])
    {
        if (isset($field['raw'])) {
            $cellContent = $field['raw'];
            if (empty($field['no_escaping'])) {
                $field['raw'] = h($field['raw']);
            }
        } else if (isset($field['formatter'])) {
            $cellContent = $field['formatter']($this->getValueFromObject($field), $this->item);
        } else if (isset($field['type'])) {
            $cellContent = $this->btHelper->getView()->element($this->getElementPath($field['type']), [
                'data' => $this->item,
                'field' => $field
            ]);
        } else {
            $cellContent = h($this->getValueFromObject($field));
        }
        foreach (['info', 'warning', 'danger'] as $message_type) {
            if (!empty($field[$message_type])) {
                $cellContent .= sprintf(' <span class="text-%s">%s</span>', $message_type, $field[$message_type]);
            }
        }
        return $this->genNode('td', [
            'class' => [
                'col-8 col-sm-10',
                !empty($field['_cellVariant']) ? "bg-{$field['_cellVariant']}" : ''
            ]
        ], $cellContent);
    }

    private function getValueFromObject($field)
    {
        if (is_array($field)) {
            $key = $field['path'];
        } else {
            $key = $field;
        }
        $cellValue = Hash::get($this->item, $key);
        return $cellValue;
    }

    private function getElementPath($type)
    {
        return sprintf(
            '%s%sField',
            $this->options['elementsRootPath'] ?? '',
            $type
        );
    }

    private function genCaption()
    {
        return !empty($this->caption) ? $this->genNode('caption', [], h($this->caption)) : '';
    }
}

class BoostrapButton extends BootstrapGeneric
{
    private $defaultOptions = [
        'id' => '',
        'text' => '',
        'html' => null,
        'variant' => 'primary',
        'outline' => false,
        'size' => '',
        'icon' => null,
        'image' => null,
        'class' => [],
        'type' => 'button',
        'nodeType' => 'button',
        'title' => '',
        'params' => [],
        'badge' => false
    ];

    private $bsClasses = [];

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => array_merge(BootstrapGeneric::$variants, ['link', 'text']),
            'size' => ['', 'xs', 'sm', 'lg'],
            'type' => ['button', 'submit', 'reset']
        ];
        if (empty($options['class'])) {
            $options['class'] = '';
        }
        $options['class'] = !is_array($options['class']) ? [$options['class']] : $options['class'];
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();

        if (!empty($this->options['id'])) {
            $this->options['params']['id'] = $this->options['id'];
        }

        $this->bsClasses[] = 'btn';
        if ($this->options['outline']) {
            $this->bsClasses[] = "btn-outline-{$this->options['variant']}";
        } else {
            $this->bsClasses[] = "btn-{$this->options['variant']}";
        }
        if (!empty($this->options['size'])) {
            $this->bsClasses[] = "btn-{$this->options['size']}";
        }
        if ($this->options['variant'] == 'text') {
            $this->bsClasses[] = 'p-0';
            $this->bsClasses[] = 'lh-1';
        }
    }

    public function button()
    {
        return $this->genButton();
    }

    private function genButton()
    {
        $html = $this->openNode($this->options['nodeType'], array_merge($this->options['params'], [
            'class' => array_merge($this->options['class'], $this->bsClasses),
            'role' => "alert",
            'type' => $this->options['type'],
            'title' => h($this->options['title']),
        ]));

        $html .= $this->genIcon();
        $html .= $this->genImage();
        $html .= $this->genContent();
        if (!empty($this->options['badge'])) {
            $bsBadge = new BoostrapBadge($this->options['badge']);
            $html .= $bsBadge->badge();
        }
        $html .= $this->closeNode($this->options['nodeType']);
        return $html;
    }

    private function genIcon()
    {
        if (!empty($this->options['icon'])) {
            $bsIcon = new BoostrapIcon($this->options['icon'], [
                'class' => [(!empty($this->options['text']) ? 'me-1' : '')]
            ]);
            return $bsIcon->icon();
        }
        return '';
    }

    private function genImage()
    {
        if (!empty($this->options['image'])) {
            return $this->genNode('img', [
                'src' => $this->options['image']['path'] ?? '',
                'class' => ['img-fluid', 'me-1'],
                'width' => '26',
                'height' => '26',
                'alt' => $this->options['image']['alt'] ?? ''
            ]);
        }
        return '';
    }

    private function genContent()
    {
        return !is_null($this->options['html']) ? $this->options['html'] : $this->options['text'];
    }
}

class BoostrapBadge extends BootstrapGeneric
{
    private $defaultOptions = [
        'text' => '',
        'variant' => 'primary',
        'pill' => false,
        'title' => '',
        'class' => [],
    ];

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->options['class'] = is_array($this->options['class']) ? $this->options['class'] : [$this->options['class']];
        $this->checkOptionValidity();
    }

    public function badge()
    {
        return $this->genBadge();
    }

    private function genBadge()
    {
        $html = $this->genNode('span', [
            'class' => array_merge($this->options['class'], [
                'ms-1',
                'badge',
                "bg-{$this->options['variant']}",
                $this->getTextClassForVariant($this->options['variant']),
                $this->options['pill'] ? 'rounded-pill' : '',
            ]),
            'title' => $this->options['title']
        ], h($this->options['text']));
        return $html;
    }
}

class BoostrapIcon extends BootstrapGeneric
{
    private $icon = '';
    private $defaultOptions = [
        'class' => [],
        'title' => '',
        'params' => [],
    ];

    function __construct($icon, $options = [])
    {
        $this->icon = $icon;
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function icon()
    {
        return $this->genIcon();
    }

    private function genIcon()
    {
        $html = $this->genNode('span', array_merge([
            'class' => array_merge(
                is_array($this->options['class']) ? $this->options['class'] : [$this->options['class']],
                ["fa fa-{$this->icon}"]
            ),
            'title' => h($this->options['title'])
        ], $this->options['params']));
        return $html;
    }
}

class BoostrapModal extends BootstrapGeneric
{
    private $defaultOptions = [
        'size' => '',
        'centered' => true,
        'scrollable' => true,
        'backdropStatic' => false,
        'title' => '',
        'titleHtml' => false,
        'body' => '',
        'bodyHtml' => false,
        'footerHtml' => false,
        'confirmText' => 'Confirm',
        'cancelText' => 'Cancel',
        'modalClass' => [''],
        'headerClass' => [''],
        'bodyClass' => [''],
        'footerClass' => [''],
        'type' => 'ok-only',
        'variant' => '',
        'confirmFunction' => '', // Will be called with the following arguments confirmFunction(modalObject, tmpApi)
        'cancelFunction' => ''
    ];

    private $bsClasses = null;

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'size' => ['sm', 'lg', 'xl', ''],
            'type' => ['ok-only', 'confirm', 'confirm-success', 'confirm-warning', 'confirm-danger', 'custom'],
            'variant' =>  array_merge(BootstrapGeneric::$variants, ['']),
        ];
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function modal()
    {
        return $this->genModal();
    }

    private function genModal()
    {
        $this->options['modalClass'] = !empty($this->options['modalClass']) && !is_array($this->options['modalClass']) ? [$this->options['modalClass']] : $this->options['modalClass'];
        $dialog = $this->openNode('div', [
            'class' => array_merge(
                ['modal-dialog', (!empty($this->options['size'])) ? "modal-{$this->options['size']}" : ''],
                $this->options['modalClass']
            ),
        ]);
        $content = $this->openNode('div', [
            'class' => ['modal-content'],
        ]);
        $header = $this->genHeader();
        $body = $this->genBody();
        $footer = $this->genFooter();
        $closedDiv = $this->closeNode('div');

        $html = "{$dialog}{$content}{$header}{$body}{$footer}{$closedDiv}{$closedDiv}";
        return $html;
    }

    private function genHeader()
    {
        $header = $this->openNode('div', ['class' => array_merge(['modal-header'], $this->options['headerClass'])]);
        if (!empty($this->options['titleHtml'])) {
            $header .= $this->options['titleHtml'];
        } else {
            $header .= $this->genNode('h5', ['class' => ['modal-title']], h($this->options['title']));
        }
        if (empty($this->options['backdropStatic'])) {
            $header .= $this->genericCloseButton('modal');
        }
        $header .= $this->closeNode('div');
        return $header;
    }

    private function genBody()
    {
        $body = $this->openNode('div', ['class' => array_merge(['modal-body'], $this->options['bodyClass'])]);
        if (!empty($this->options['bodyHtml'])) {
            $body .= $this->options['bodyHtml'];
        } else {
            $body .= h($this->options['body']);
        }
        $body .= $this->closeNode('div');
        return $body;
    }

    private function genFooter()
    {
        $footer = $this->openNode('div', [
            'class' => array_merge(['modal-footer'], $this->options['footerClass']),
            'data-custom-footer' => $this->options['type'] == 'custom'
        ]);
        if (!empty($this->options['footerHtml'])) {
            $footer .= $this->options['footerHtml'];
        } else {
            $footer .= $this->getFooterBasedOnType();
        }
        $footer .= $this->closeNode('div');
        return $footer;
    }

    private function getFooterBasedOnType()
    {
        if ($this->options['type'] == 'ok-only') {
            return $this->getFooterOkOnly();
        } else if (str_contains($this->options['type'], 'confirm')) {
            return $this->getFooterConfirm();
        } else if ($this->options['type'] == 'custom') {
            return $this->getFooterCustom();
        } else {
            return $this->getFooterOkOnly();
        }
    }

    private function getFooterOkOnly()
    {
        return (new BoostrapButton([
            'variant' => 'primary',
            'text' => __('Ok'),
            'params' => [
                'data-bs-dismiss' => $this->options['confirmFunction'] ? '' : 'modal',
                'onclick' => $this->options['confirmFunction']
            ]
        ]))->button();
    }

    private function getFooterConfirm()
    {
        if ($this->options['type'] == 'confirm') {
            $variant = 'primary';
        } else {
            $variant = explode('-', $this->options['type'])[1];
        }
        $buttonCancel = (new BoostrapButton([
            'variant' => 'secondary',
            'text' => h($this->options['cancelText']),
            'params' => [
                'data-bs-dismiss' => 'modal',
                'onclick' => $this->options['cancelFunction']
            ]
        ]))->button();

        $buttonConfirm = (new BoostrapButton([
            'variant' => $variant,
            'text' => h($this->options['confirmText']),
            'class' => 'modal-confirm-button',
            'params' => [
                // 'data-bs-dismiss' => $this->options['confirmFunction'] ? '' : 'modal',
                'data-confirmFunction' => sprintf('%s', $this->options['confirmFunction'])
            ]
        ]))->button();
        return $buttonCancel . $buttonConfirm;
    }

    private function getFooterCustom()
    {
        $buttons = [];
        foreach ($this->options['footerButtons'] as $buttonConfig) {
            $buttons[] = (new BoostrapButton([
                'variant' => h($buttonConfig['variant'] ?? 'primary'),
                'text' => h($buttonConfig['text']),
                'class' => 'modal-confirm-button',
                'params' => [
                    'data-bs-dismiss' => !empty($buttonConfig['clickFunction']) ? '' : 'modal',
                    'data-clickFunction' => sprintf('%s', $buttonConfig['clickFunction'])
                ]
            ]))->button();
        }
        return implode('', $buttons);
    }
}

class BoostrapCard extends BootstrapGeneric
{
    private $defaultOptions = [
        'variant' => '',
        'headerText' => '',
        'footerText' => '',
        'bodyText' => '',
        'headerHTML' => '',
        'footerHTML' => '',
        'bodyHTML' => '',
        'class' => '',
        'headerClass' => '',
        'bodyClass' => '',
        'footerClass' => '',
    ];

    public function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => array_merge(BootstrapGeneric::$variants, ['']),
        ];
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function card()
    {
        return $this->genCard();
    }

    private function genCard()
    {
        $card = $this->genNode('div', [
            'class' => [
                'card',
                !empty($this->options['variant']) ? "bg-{$this->options['variant']}" : '',
                !empty($this->options['variant']) ? $this->getTextClassForVariant($this->options['variant']) : '',
                h(is_array($this->options['class']) ? implode(' ', $this->options['class']) : $this->options['class']),
            ],
        ], implode('', [$this->genHeader(), $this->genBody(), $this->genFooter()]));
        return $card;
    }

    private function genHeader()
    {
        if (empty($this->options['headerHTML']) && empty($this->options['headerText'])) {
            return '';
        }
        $content = !empty($this->options['headerHTML']) ? $this->options['headerHTML'] : h($this->options['headerText']);
        $header = $this->genNode('div', [
            'class' => [
                'card-header',
                h($this->options['headerClass']),
            ],
        ], $content);
        return $header;
    }

    private function genBody()
    {
        if (empty($this->options['bodyHTML']) && empty($this->options['bodyText'])) {
            return '';
        }
        $content = !empty($this->options['bodyHTML']) ? $this->options['bodyHTML'] : h($this->options['bodyText']);
        $body = $this->genNode('div', [
            'class' => [
                'card-body',
                h($this->options['bodyClass']),
            ],
        ], $content);
        return $body;
    }

    private function genFooter()
    {
        if (empty($this->options['footerHTML']) && empty($this->options['footerText'])) {
            return '';
        }
        $content = !empty($this->options['footerHTML']) ? $this->options['footerHTML'] : h($this->options['footerText']);
        $footer = $this->genNode('div', [
            'class' => [
                'card-footer',
                h($this->options['footerClass']),
            ],
        ], $content);
        return $footer;
    }
}

class BoostrapSwitch extends BootstrapGeneric
{
    private $defaultOptions = [
        'label' => '',
        'variant' => 'primary',
        'disabled' => false,
        'checked' => false,
        'title' => '',
        'class' => [],
        'attrs' => [],
    ];

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function switch()
    {
        return $this->genSwitch();
    }

    private function genSwitch()
    {
        $tmpId = 'tmp-' . mt_rand();
        $html = $this->genNode('div', [
            'class' => [
                'form-check form-switch',
            ],
            'title' => $this->options['title']
        ], implode('', [
            $this->genNode('input', array_merge([
                'type' => "checkbox",
                'class' => 'form-check-input',
                'id' => $tmpId,
                ($this->options['disabled'] ? 'disabled' : '') => '',
                ($this->options['checked'] ? 'checked' : '') => $this->options['checked'] ? 'checked' : '',
            ], $this->options['attrs'])),
            $this->genNode('label', [
                'class' => 'form-check-label',
                'for' => $tmpId,
            ], h($this->options['label']))
        ]));
        return $html;
    }
}

class BoostrapNotificationBuble extends BootstrapGeneric
{
    private $defaultOptions = [
        'label' => '',
        'variant' => 'warning',
        'borderVariant' => 'ligth',
        'title' => 'Notification',
        'class' => [],
        'attrs' => [],
    ];

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->defaultOptions['label'] =  __('New notifications');
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
        if (!empty($this->options['attrs']['style'])) {
            $this->options['attrs']['style'] += 'box-shadow: 0 0.125rem 0.25rem #00000050;';
        } else {
            $this->options['attrs']['style'] = 'box-shadow: 0 0.125rem 0.25rem #00000050;';
        }
    }

    public function notificationBubble()
    {
        return $this->genNotificationBubble();
    }

    private function genNotificationBubble()
    {
        $tmpId = 'tmp-' . mt_rand();
        $html = $this->genNode('span', [
            'id' => $tmpId,
            'class' => [
                'position-absolute',
                'top-0',
                'start-100',
                'translate-middle',
                'p-1',
                'border border-2 rounded-circle',
                "border-{$this->options['borderVariant']}",
                "bg-{$this->options['variant']}",
            ],
            'title' => $this->options['title']
        ], $this->genNode('span', [
            'class' => [
            ],
            $this->options['label']
        ]));
        return $html;
    }
}

class BoostrapProgress extends BootstrapGeneric
{
    private $defaultOptions = [
        'value' => 0,
        'total' => 100,
        'text' => '',
        'title' => '',
        'variant' => 'primary',
        'height' => '',
        'striped' => false,
        'animated' => false,
        'label' => true
    ];

    function __construct($options)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function progress()
    {
        return $this->genProgress();
    }

    private function genProgress()
    {
        $percentage = round(100 * $this->options['value'] / $this->options['total']);
        $heightStyle = !empty($this->options['height']) ? sprintf('height: %s;', h($this->options['height'])) : '';
        $widthStyle = sprintf('width: %s%%;', $percentage);
        $label = $this->options['label'] ? "{$percentage}%" : '';
        $pb  = $this->genNode('div', [
            'class' => [
                'progress-bar',
                "bg-{$this->options['variant']}",
                $this->options['striped'] ? 'progress-bar-striped' : '',
                $this->options['animated'] ? 'progress-bar-animated' : '',
            ],
            'role' => "progressbar",
            'aria-valuemin' => "0", 'aria-valuemax' => "100", 'aria-valuenow' => $percentage,
            'style' => "${widthStyle}",
            'title' => $this->options['title']
        ], $label);
        $container = $this->genNode('div', [
            'class' => [
                'progress',
            ],
            'style' => "${heightStyle}",
            'title' => h($this->options['title']),
        ], $pb);
        return $container;
    }
}

class BoostrapCollapse extends BootstrapGeneric
{
    private $defaultOptions = [
        'title' => '',
        'open' => false,
    ];

    function __construct($options, $content, $btHelper)
    {
        $this->allowedOptionValues = [];
        $this->processOptions($options);
        $this->content = $content;
        $this->btHelper = $btHelper;
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function collapse()
    {
        return $this->genCollapse();
    }

    private function genControl()
    {
        $html = $this->genNode('a', [
            'class' => ['text-decoration-none'],
            'data-bs-toggle' => 'collapse',
            'href' => '#collapseExample',
            'role' => 'button',
            'aria-expanded' => 'false',
            'aria-controls' => 'collapseExample',
        ], h($this->options['title']));
        return $html;
    }

    private function genContent()
    {
        $content = $this->genNode('div', [
            'class' => 'card',
        ], $this->content);
        $container = $this->genNode('div', [
            'class' => ['collapse', $this->options['open'] ? 'show' : ''],
            'id' => 'collapseExample',
        ], $content);
        return $container;
    }

    private function genCollapse()
    {
        $html = $this->genControl();
        $html .= $this->genContent();
        return $html;
    }
}

class BoostrapAccordion extends BootstrapGeneric
{
    private $defaultOptions = [
        'stayOpen' => true,
        'class' => [],
    ];

    function __construct($options, $content, $btHelper)
    {
        $this->allowedOptionValues = [];
        $this->content = $content;
        $this->btHelper = $btHelper;
        $this->processOptions($options);
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
        if (!is_array($this->options['class']) && !empty($this->options['class'])) {
            $this->options['class'] = [$this->options['class']];
        }
        $this->seed = 'acc-' . mt_rand();
        $this->contentSeeds = [];
        foreach ($this->content as $accordionItem) {
            $this->contentSeeds[] = mt_rand();
        }
    }

    public function accordion()
    {
        return $this->genAccordion();
    }

    private function genHeader($accordionItem, $i)
    {
        $html = $this->openNode('h2', [
            'class' => ['accordion-header'],
            'id' => 'head-' . $this->contentSeeds[$i]
        ]);
        $content = !empty($accordionItem['header']['html']) ? $accordionItem['header']['html'] : h($accordionItem['header']['title'] ?? '- no title -');
        $buttonOptions = [
            'class' => array_merge(['accordion-button', empty($accordionItem['_open']) ? 'collapsed' : ''], $accordionItem['header']['__class'] ?? []),
            'type' => 'button',
            'data-bs-toggle' => 'collapse',
            'data-bs-target' => '#body-' . $this->contentSeeds[$i],
            'aria-expanded' => 'false',
            'aria-controls' => 'body-' . $this->contentSeeds[$i],
        ];
        $html .= $this->genNode('button', $buttonOptions, $content);
        $html .= $this->closeNode(('h2'));
        return $html;
    }

    private function genBody($accordionItem, $i)
    {
        $content = $this->genNode('div', [
            'class' => ['accordion-body']
        ], $accordionItem['body']);
        $divOptions = [
            'class' => array_merge(['accordion-collapse collapse', empty($accordionItem['_open']) ? '' : 'show'], $accordionItem['body']['__class'] ?? []),
            'id' => 'body-' . $this->contentSeeds[$i],
            'aria-labelledby' => 'head-' . $this->contentSeeds[$i],
        ];
        if (!empty($this->options['stayOpen'])) {
            $divOptions['data-bs-parent'] = '#' . $this->seed;
        }
        $html = $this->genNode('div', $divOptions, $content);
        return $html;
    }

    private function genAccordion()
    {
        $html = $this->openNode('div', [
            'class' => array_merge(['accordion'], $this->options['class']),
            'id' => $this->seed
        ]);
        foreach ($this->content as $i => $accordionItem) {
            $html .= $this->openNode('div', [
                'class' => array_merge(['accordion-item'], $accordionItem['__class'] ?? [])
            ]);
            $html .= $this->genHeader($accordionItem, $i);
            $html .= $this->genBody($accordionItem, $i);
            $html .= $this->closeNode('div');
        }
        $html .= $this->closeNode('div');
        return $html;
    }
}

class BoostrapProgressTimeline extends BootstrapGeneric
{
    private $defaultOptions = [
        'steps' => [],
        'selected' => 0,
        'variant' => 'info',
        'variantInactive' => 'secondary',
    ];

    function __construct($options, $btHelper)
    {
        $this->allowedOptionValues = [
            'variant' => BootstrapGeneric::$variants,
            'variantInactive' => BootstrapGeneric::$variants,
        ];
        $this->processOptions($options);
        $this->btHelper = $btHelper;
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
    }

    public function progressTimeline()
    {
        return $this->genProgressTimeline();
    }

    private function getStepIcon($step, $i, $nodeActive, $lineActive)
    {
        $icon = $this->genNode('b', [
            'class' => [
                !empty($step['icon']) ? h($this->btHelper->FontAwesome->getClass($step['icon'])) : '',
                $this->getTextClassForVariant($this->options['variant'])
            ],
        ], empty($step['icon']) ? h($i + 1) : '');
        $iconContainer = $this->genNode('span', [
            'class' => [
                'd-flex', 'align-items-center', 'justify-content-center',
                'rounded-circle',
                $nodeActive ? "bg-{$this->options['variant']}" : "bg-{$this->options['variantInactive']}"
            ],
            'style' => 'width:50px; height:50px'
        ], $icon);
        $li = $this->genNode('li', [
            'class' => [
                'd-flex', 'flex-column',
                $nodeActive ? 'progress-active' : 'progress-inactive',
            ],
        ], $iconContainer);
        $html = $li . $this->getHorizontalLine($i, $nodeActive, $lineActive);
        return $html;
    }

    private function getHorizontalLine($i, $nodeActive, $lineActive)
    {
        $stepCount = count($this->options['steps']);
        if ($i == $stepCount - 1) {
            return '';
        }
        $progressBar = (new BoostrapProgress([
            'label' => false,
            'value' => $nodeActive ? ($lineActive ? 100 : 50) : 0,
            'height' => '2px',
            'variant' => $this->options['variant']
        ]))->progress();
        $line = $this->genNode('span', [
            'class' => [
                'progress-line',
                'flex-grow-1', 'align-self-center',
                $lineActive ? "bg-{$this->options['variant']}" : ''
            ],
        ], $progressBar);
        return $line;
    }

    private function getStepText($step, $isActive)
    {
        return $this->genNode('li', [
            'class' => [
                'text-center',
                'fw-bold',
                $isActive ? 'progress-active' : 'progress-inactive',
            ],
        ], h($step['text'] ?? ''));
    }

    private function genProgressTimeline()
    {
        $iconLis = '';
        $textLis = '';
        foreach ($this->options['steps'] as $i => $step) {
            $nodeActive = $i <= $this->options['selected'];
            $lineActive = $i < $this->options['selected'];
            $iconLis .= $this->getStepIcon($step, $i, $nodeActive, $lineActive);
            $textLis .= $this->getStepText($step, $nodeActive);
        }
        $ulIcons = $this->genNode('ul', [
            'class' => [
                'd-flex', 'justify-content-around',
            ],
        ], $iconLis);
        $ulText = $this->genNode('ul', [
            'class' => [
                'd-flex', 'justify-content-between',
            ],
        ], $textLis);
        $html = $this->genNode('div', [
            'class' => ['progress-timeline', 'mw-75', 'mx-auto']
        ], $ulIcons . $ulText);
        return $html;
    }
}

class BootstrapListGroup extends BootstrapGeneric
{
    private $defaultOptions = [
        'hover' => false,
    ];

    private $bsClasses = null;

    function __construct($options, $data, $btHelper)
    {
        $this->data = $data;
        $this->processOptions($options);
        $this->btHelper = $btHelper;
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
    }

    public function listGroup()
    {
        return $this->genListGroup();
    }

    private function genListGroup()
    {
        $html = $this->openNode('div', [
            'class' => ['list-group',],
        ]);
        foreach ($this->data as $item) {
            $html .= $this->genItem($item);
        }
        $html .= $this->closeNode('div');
        return $html;
    }

    private function genItem($item)
    {
        if (!empty($item['heading'])) { // complex layout with heading, badge and body
            $html = $this->genNode('a', [
                'class' => ['list-group-item', (!empty($this->options['hover']) ? 'list-group-item-action' : ''),],
            ], implode('', [
                $this->genHeadingGroup($item),
                $this->genBody($item),
            ]));
        } else { // simple layout with just <li>-like elements
            $html = $this->genNode('a', [
                'class' => ['list-group-item', 'd-flex', 'align-items-center', 'justify-content-between'],
            ], implode('', [
                h($item['text']),
                $this->genBadge($item)
            ]));
        }
        return $html;
    }

    private function genHeadingGroup($item)
    {
        $html = $this->genNode('div', [
            'class' => ['d-flex', 'w-100', 'justify-content-between',],
        ], implode('', [
            $this->genHeading($item),
            $this->genBadge($item)
        ]));
        return $html;
    }

    private function genHeading($item)
    {
        if (empty($item['heading'])) {
            return '';
        }
        return $this->genNode('h5', [
            'class' => ['mb-1'],
        ], h($item['heading']));
    }

    private function genBadge($item)
    {
        if (empty($item['badge'])) {
            return '';
        }
        return $this->genNode('span', [
            'class' => ['badge rounded-pill', (!empty($item['badge-variant']) ? "bg-{$item['badge-variant']}" : 'bg-primary')],
        ], h($item['badge']));
    }

    private function genBody($item)
    {
        if (!empty($item['bodyHTML'])) {
            return $item['bodyHTML'];
        }
        return !empty($item['body']) ? h($item['body']) : '';
    }
}


class BoostrapDropdownMenu extends BootstrapGeneric
{
    private $defaultOptions = [
        'dropdown-class' => [],
        'toggle-button' => [],
        'menu' => [],
        'direction' => 'end',
        'alignment' => 'start',
        'submenu_alignment' => 'start',
        'submenu_direction' => 'end',
        'submenu_classes' => [],
    ];

    function __construct($options, $btHelper)
    {
        $this->allowedOptionValues = [
            'direction' => ['start', 'end', 'up', 'down'],
            'alignment' => ['start', 'end'],
        ];
        $this->processOptions($options);
        $this->menu = $this->options['menu'];
        $this->btHelper = $btHelper;
    }

    private function processOptions($options)
    {
        $this->options = array_merge($this->defaultOptions, $options);
        if (!empty($this->options['dropdown-class']) && !is_array($this->options['dropdown-class'])) {
            $this->options['dropdown-class'] = [$this->options['dropdown-class']];
        }
        $this->checkOptionValidity();
    }

    public function dropdownMenu()
    {
        return $this->fullDropdown();
    }

    public function fullDropdown()
    {
        return $this->genDropdownWrapper($this->genDropdownToggleButton(), $this->genDropdownMenu($this->menu));
    }

    public function genDropdownWrapper($toggle = '', $menu = '', $direction = null, $classes = null)
    {
        $classes = !is_null($classes) ? $classes :  $this->options['dropdown-class'];
        $direction = !is_null($direction) ? $direction : $this->options['direction'];
        $content = $toggle . $menu;
        $html = $this->genNode('div', array_merge(
            $this->options['params'],
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

    public function genDropdownToggleButton()
    {
        $defaultOptions = [
            'class' => ['dropdown-toggle'],
            'params' => [
                'data-bs-toggle' => 'dropdown',
                'aria-expanded' => 'false',
            ]
        ];
        $options = array_merge($this->options['toggle-button'], $defaultOptions);
        return $this->btHelper->button($options);
    }

    private function genDropdownMenu($entries, $alignment = null)
    {
        $alignment = !is_null($alignment) ? $alignment : $this->options['alignment'];
        $html = $this->genNode('div', [
            'class' => ['dropdown-menu', "dropdown-menu-{$alignment}"],
        ], $this->genEntries($entries));
        return $html;
    }

    private function genEntries($entries)
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

    private function genEntry($entry)
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
            $bsBadge = new BoostrapBadge(array_merge(
                ['class' => ['ms-auto']],
                $entry['badge']
            ));
            $badge = $bsBadge->badge();
        }

        if (!empty($entry['header'])) {
            return $this->genNode('h6', [
                'class' => ['dropdown-header',],
            ], $icon . h($entry['text']) . $badge);
        }

        $classes = ['dropdown-item'];
        $params = ['href' => '#'];

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

        $labelContent = sprintf('%s%s',
            h($entry['text']),
            !empty($entry['sup']) ? $this->genNode('sup', ['class' => 'ms-1 text-muted'], $entry['sup']) : ''
        );
        $label = $this->genNode('span', ['class' => 'mx-1'], $labelContent);
        $content = $icon . $label . $badge;

        return $this->genNode('a', array_merge([
            'class' => $classes,
        ], $params), $content);
    }
}
