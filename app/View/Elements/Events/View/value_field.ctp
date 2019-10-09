<?php
$sigDisplay = $object['value'];

switch ($object['type']) {
    case 'attachment':
    case 'malware-sample':
        if ($object['type'] === 'attachment' && isset($object['image'])) {
            if (extension_loaded('gd')) {
                $img = '<it class="fa fa-spin fa-spinner" style="font-size: large; left: 50%; top: 50%;"></it>';
                $img .= '<img class="screenshot screenshot-collapsed useCursorPointer img-rounded hidden" src="' . $baseurl . '/attributes/viewPicture/' . h($object['id']) . '/1' . '" title="' . h($object['value']) . '" onload="$(this).show(200); $(this).parent().find(\'.fa-spinner\').remove();"/>';
                echo $img;
            } else {
                $extension = pathinfo($object['value'], PATHINFO_EXTENSION);
                $uri = 'data:image/' . strtolower(h($extension)) . ';base64,' . h($object['image']);
                echo '<img class="screenshot screenshot-collapsed useCursorPointer" src="' . $uri . '" title="' . h($object['value']) . '" />';
            }
        } else {
            $filenameHash = explode('|', h($object['value']));
            if (strrpos($filenameHash[0], '\\')) {
                $filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
                $filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
                echo h($filepath);
            } else {
                $filename = $filenameHash[0];
            }

            $url = array('controller' => 'attributes', 'action' => 'download', $object['id']);
            echo $this->Html->link($filename, $url, array('class' => $linkClass));
            if (isset($filenameHash[1])) {
                echo '<br />' . $filenameHash[1];
            }
        }
        break;

    case 'vulnerability':
        $cveUrl = Configure::read('MISP.cveurl') ?: 'https://cve.circl.lu/cve/';
        echo $this->Html->link($sigDisplay, $cveUrl . $sigDisplay, array('target' => '_blank', 'class' => $linkClass));
        break;

    case 'weakness':
        $cweUrl = Configure::read('MISP.cweurl') ?: 'https://cve.circl.lu/cwe/';
        $link = $cweUrl . explode("-", $sigDisplay)[1];
        echo $this->Html->link($sigDisplay, $link, array('target' => '_blank', 'class' => $linkClass));
        break;

    case 'link':
        echo $this->Html->link($sigDisplay, $sigDisplay, array('class' => $linkClass));
        break;

    case 'cortex':
        echo '<div class="cortex-json" data-cortex-json="' . h($object['value']) . '">' . __('Cortex object') . '</div>';
        break;

    case 'text':
        if (in_array($object['category'], array('External analysis', 'Internal reference')) && Validation::uuid($object['value'])) {
            $url = array('controller' => 'events', 'action' => 'view', $object['value']);
            echo $this->Html->link($object['value'], $url, array('class' => $linkClass));
        } else {
            $sigDisplay = str_replace("\r", '', h($sigDisplay));
            $sigDisplay = str_replace(" ", '&nbsp;', $sigDisplay);
            echo $sigDisplay;
        }
        break;

    case 'hex':
        $sigDisplay = str_replace("\r", '', $sigDisplay);
        echo '<span class="hex-value" title="' . __('Hexadecimal representation') . '">' . nl2br(h($sigDisplay)) . '</span>&nbsp;';
        echo '<span role="button" tabindex="0" aria-label="' . __('Switch to binary representation') . '" class="icon-repeat hex-value-convert useCursorPointer" title="' . __('Switch to binary representation') . '"></span>';
        break;

    default:
        if (strpos($object['type'], '|') !== false) {
            $separator = in_array($object['type'], array('ip-dst|port', 'ip-src|port')) ? ':' : '<br />';
            $valuePieces = explode('|', $object['value']);
            foreach ($valuePieces as $k => $v) {
                $valuePieces[$k] = h($v);
            }
            echo implode($separator, $valuePieces);
        } else {
            $sigDisplay = str_replace("\r", '', $sigDisplay);
            echo h($sigDisplay);
        }
}

if (isset($object['validationIssue'])) {
    echo ' <span class="fa fa-exclamation-triangle" title="' . __('Warning, this doesn\'t seem to be a legitimate ') . strtoupper(h($object['type'])) . __(' value') . '">&nbsp;</span>';
}
