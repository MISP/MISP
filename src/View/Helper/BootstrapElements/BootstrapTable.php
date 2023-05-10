<?php

namespace App\View\Helper\BootstrapElements;

use Cake\Utility\Hash;
use Cake\Utility\Inflector;

use App\View\Helper\BootstrapGeneric;
use App\View\Helper\BootstrapHelper;

/**
 * Creates a table from 2-dimensional data $items.
 * Perfect to display a list of objects.
 * 
 * # Options for table
 *  - striped, bordered, borderless, hover, small: Default bootstrap behavior
 *  - variant: Variant to apply on the entire table
 *  - tableClass: A list of class to add on the table container
 *  - bodyClass: A list of class to add on the tbody container
 *  - id: The ID to use for the table
 *  - caption: Optional table caption
 *  - elementsRootPath: Root path to use when item are relying on cakephp's element. See options for fields
 * 
 * # Options for fields
 *  - label: The name of the field to be displayed as a label
 *  - labelHtml: The HTML of the field to be displayed as a label
 *  - class: Additional classes to add for that row
 *  - path: The path to be fed to Hash::get() in order to get the value from the $item
 *  - element: The type of element to use combined with $elementsRootPath from the table's option
 *  - formatter: A callback function to format the value
 *  - columnVariant: The bootstrap variant to be applied on the cell
 *  - notice_$variant: A text with the passed variant to be append at the end. $variant can be any valid bootstrap variant. Example: `notice_warning` or `notice_info`.
 * 
 * # Special fields for $items
 * - _rowVariant: The bootstrap variant to be applied on the row
 * 
 * # Usage:
 *     $this->Bootstrap->table(
 *         [
 *             'hover' => false,
 *             'striped' => false,
 *         ],
 *         [
 *             'items' => [
 *                 ['column 1' => 'col1', 'column 2' => 'col2', 'key1' => 'val1', 'key2' => true],
 *                 ['column 1' => 'col1', 'column 2' => 'col2', 'key1' => 'val2', 'key2' => false,'_rowVariant' => 'success'],
 *                 ['column 1' => 'col1', 'column 2' => 'col2', 'key1' => 'val3', 'key2' => true],
 *             ],
 *             'fields' => [
 *                 'column 1',
 *                 [
 *                     'path' => 'column 2',
 *                     'label' => 'COLUMN 2',
 *                     'columnVariant' => 'danger',
 *                 ],
 *                 [
 *                     'labelHtml' => '<i>column 3</i>',
 *                 ],
 *                 [
 *                     'path' => 'key1',
 *                     'label' => __('Field'),
 *                     'formatter' => function ($field, $row) {
 *                         return sprintf('<i>%s</i>', h($field));
 *                     }
 *                 ],
 *                 [
 *                     'path' => 'key2',
 *                     'element' => 'boolean',
 *                 ],
 *             ],
 *             'caption' => 'This is a caption'
 *         ]
 *     );
 */
class BootstrapTable extends BootstrapGeneric
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
        'id' => '',
        'caption' => '',
        'elementsRootPath' => '/genericElements/SingleViews/Fields/',
    ];

    function __construct(array $options, array $data, BootstrapHelper $btHelper)
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

    private function processOptions(array $options): void
    {
        $this->options = array_merge($this->defaultOptions, $options);
        $this->checkOptionValidity();
        $this->options['tableClass'] = $this->convertToArrayIfNeeded($this->options['tableClass']);
        $this->options['bodyClass'] = $this->convertToArrayIfNeeded($this->options['bodyClass']);
        $this->options['headerClass'] = $this->convertToArrayIfNeeded($this->options['headerClass']);
    }

    public function table(): string
    {
        return $this->genTable();
    }

    private function genTable(): string
    {
        $html = $this->nodeOpen('table', [
            'class' => [
                'table',
                "table-{$this->options['variant']}",
                $this->options['striped'] ? 'table-striped' : '',
                $this->options['bordered'] ? 'table-bordered' : '',
                $this->options['borderless'] ? 'table-borderless' : '',
                $this->options['hover'] ? 'table-hover' : '',
                $this->options['small'] ? 'table-sm' : '',
                implode(' ', $this->options['tableClass']),
                !empty($this->options['variant']) ? "table-{$this->options['variant']}" : '',
            ],
            'id' => $this->options['id'] ?? ''
        ]);

        $html .= $this->genCaption();
        $html .= $this->genHeader();
        $html .= $this->genBody();

        $html .= $this->nodeClose('table');
        return $html;
    }

    private function genHeader(): string
    {
        $head =  $this->nodeOpen('thead', [
            'class' => $this->options['headerClass'],
        ]);
        $head .= $this->nodeOpen('tr');
        foreach ($this->fields as $i => $field) {
            if (is_array($field)) {
                if (!empty($field['labelHtml'])) {
                    $label = $field['labelHtml'];
                } else {
                    $label = !empty($field['label']) ? $field['label'] : Inflector::humanize($field['path']);
                    $label = h($label);
                }
            } else {
                $label = Inflector::humanize($field);
                $label = h($label);
            }
            $head .= $this->node('th', [], $label);
        }
        $head .= $this->nodeClose('tr');
        $head .= $this->nodeClose('thead');
        return $head;
    }

    private function genBody(): string
    {
        $body =  $this->nodeOpen('tbody', [
            'class' => $this->options['bodyClass'],
        ]);
        foreach ($this->items as $i => $row) {
            $body .= $this->genRow($row, $i);
        }
        $body .= $this->nodeClose('tbody');
        return $body;
    }

    private function genRow(array $row, int $rowIndex): string
    {
        $html = $this->nodeOpen('tr', [
            'class' => [
                !empty($row['_rowVariant']) ? "table-{$row['_rowVariant']}" : ''
            ]
        ]);
        if (array_keys($row) !== range(0, count($row) - 1)) { // associative array
            foreach ($this->fields as $i => $field) {
                $cellValue = $this->getValueFromObject($row, $field);
                $html .= $this->genCell($cellValue, $field, $row, $rowIndex);
            }
        } else { // indexed array
            foreach ($row as $i => $cellValue) {
                $html .= $this->genCell($cellValue, $this->fields[$i], $row, $rowIndex);
            }
        }
        $html .= $this->nodeClose('tr');
        return $html;
    }

    private function genCell($value, array $field = [], array $row = [], int $rowIndex = 0): string
    {
        if (isset($field['formatter'])) {
            $cellContent = $field['formatter']($value, $row, $rowIndex);
        } else if (isset($field['element'])) {
            $cellContent = $this->btHelper->getView()->element($this->getElementPath($field['element']), [
                'data' => [$value],
                'field' => ['path' => '0']
            ]);
        } else {
            $cellContent = h($value);
        }
        return $this->node('td', [
            'class' => array_merge(
                [
                    !empty($field['columnVariant']) ? "table-{$field['columnVariant']}" : ''
                ],
                $field['class'] ?? []
            ),
        ], $cellContent);
    }

    private function getValueFromObject(array $row, $field)
    {
        $path = is_array($field) ? $field['path'] : $field;
        $cellValue = Hash::get($row, $path);
        return !is_null($cellValue) ? $cellValue : '';
    }

    private function getElementPath(string $type): string
    {
        return sprintf(
            '%s%sField',
            $this->options['elementsRootPath'] ?? '',
            $type
        );
    }

    private function genCaption(): string
    {
        return !empty($this->caption) ? $this->node('caption', [], h($this->caption)) : '';
    }
}
