<?php
App::uses('CakeNumber', 'Utility');
/*
 * An attribute's value rendered for its type. Expects a flat attribute row in
 * $attribute; rows without an id (freetext results) get no download link.
 */
$value = (string)($attribute['value'] ?? '');
$type = (string)($attribute['type'] ?? '');
$isProposal = !empty($attribute['is_proposal']);
$hoverValue = $hoverValue ?? null;

// With $hoverValue, the value's own text becomes the value hover card trigger.
$hover = function ($html) use ($hoverValue) {
    if (empty($hoverValue)) {
        return $html;
    }
    return '<span class="vp-hc-trigger" data-vp-hc-value="' . h($hoverValue) . '"'
        . ' title="' . h(__('Hover for this value\'s assessment')) . '">' . $html . '</span>';
};

$longText = function ($text) use ($hover) {
    $text = str_replace("\r", '', $text);
    $short = $text;
    if (strlen($short) > 500) {
        $short = preg_match('/^.{0,500}/su', $short, $head) ? $head[0] : substr($short, 0, 500);
    }
    if (substr_count($short, "\n") > 10) {
        $short = implode("\n", array_slice(explode("\n", $short), 0, 10));
    }
    if ($short === $text) {
        return $hover('<span class="om-value-text">' . h($text) . '</span>');
    }
    return '<span class="om-value-long">'
        . $hover('<span class="om-value-text om-value-short">' . h(rtrim($short)) . '&hellip;</span>'
            . '<span class="om-value-text om-value-full" hidden>' . h($text) . '</span>')
        . '<button type="button" class="btn btn-link btn-sm p-0 ms-1 align-baseline om-value-more"'
        . ' data-label-more="' . h(__('Show all')) . '" data-label-less="' . h(__('Show less')) . '">'
        . h(__('Show all')) . '</button>'
        . '</span>';
};

$external = function ($text, $url, $title) use ($hover) {
    return $hover('<a href="' . h($url) . '" target="_blank" rel="noreferrer noopener" title="' . h($title) . '">'
        . h($text) . '<i class="fas fa-arrow-up-right-from-square ms-1 om-value-ext"></i></a>');
};

$lines = function (array $pieces) use ($hover) {
    $out = '';
    foreach ($pieces as $piece) {
        $out .= '<span class="d-block">' . h($piece) . '</span>';
    }
    return $hover($out);
};

switch ($type) {
    case 'attachment':
    case 'malware-sample':
        $pieces = explode('|', $value, 2);
        $downloadId = $isProposal ? ($attribute['proposal_id'] ?? $attribute['id'] ?? null) : ($attribute['id'] ?? null);
        $infected = array_key_exists('infected', $attribute) ? $attribute['infected'] : false;
        if ($infected === null) {
            $confirm = __('This file was not checked by AV scan. Do you really want to download it?');
        } elseif ($infected !== false) {
            $confirm = __('According to AV scan, this file contains %s malware. Do you really want to download it?', $infected);
        } elseif ($type === 'malware-sample') {
            $confirm = __('You are going to download file that is probably malware. For your safety, the file is compressed in encrypted ZIP file. To decrypt use password `infected`.');
        } else {
            $confirm = null;
        }
        if (!empty($downloadId)) {
            $url = sprintf('%s/%s/download/%s', $baseurl, $isProposal ? 'shadow_attributes' : 'attributes', (int)$downloadId);
            echo $hover('<a href="' . h($url) . '" class="om-value-download"'
                . ($confirm !== null ? ' data-om-confirm="' . h($confirm) . '"' : '')
                . ' title="' . h(__('Download')) . '">'
                . '<i class="fas fa-download me-1"></i>' . h($pieces[0]) . '</a>');
        } else {
            echo $hover(h($pieces[0]));
        }
        if ($type === 'malware-sample') {
            echo ' <span class="badge rounded-pill om-value-zip" title="'
                . h(__('Downloads as an encrypted ZIP. Password: infected')) . '">'
                . '<i class="fas fa-lock me-1"></i>infected</span>';
        }
        if ($infected !== false && $infected !== null) {
            echo ' <span class="badge rounded-pill text-bg-danger" title="'
                . h(__('This file contains malware %s', $infected)) . '">'
                . '<i class="fas fa-virus me-1"></i>' . h($infected) . '</span>';
        }
        if (isset($pieces[1])) {
            echo '<span class="d-block text-muted font-monospace small">' . h($pieces[1]) . '</span>';
        }
        break;

    case 'vulnerability':
        echo $external($value, (Configure::read('MISP.cveurl') ?: 'https://vulnerability.circl.lu/vuln/') . $value,
            __('Show more information about this vulnerability in external tool'));
        break;

    case 'weakness':
        echo $external($value, (Configure::read('MISP.cweurl') ?: 'https://vulnerability.circl.lu/cwes/') . $value,
            __('Show more information about this weakness in external tool'));
        break;

    case 'link':
        if (preg_match('/^https?:\/\//i', $value)) {
            echo $hover('<a href="' . h($value) . '" rel="noreferrer noopener" target="_blank">' . h($value) . '</a>');
        } else {
            echo $hover(h($value));
        }
        break;

    case 'text':
        if (in_array($attribute['category'] ?? '', ['External analysis', 'Internal reference'], true)
            && Validation::uuid($value)) {
            echo $hover('<a href="' . h($baseurl . '/events/view2/' . $value) . '">' . h($value) . '</a>');
        } else {
            echo $longText($value);
        }
        break;

    case 'hex':
        echo $hover('<span class="om-value-hex font-monospace" data-hex="' . h($value) . '" title="'
            . h(__('Hexadecimal representation')) . '">' . h($value) . '</span>')
            . '<button type="button" class="btn btn-link btn-sm p-0 ms-1 align-baseline om-value-hex-toggle"'
            . ' title="' . h(__('Switch to binary representation')) . '"'
            . ' aria-label="' . h(__('Switch to binary representation')) . '"'
            . ' data-label-bin="' . h(__('Switch to binary representation')) . '"'
            . ' data-label-hex="' . h(__('Switch to hexadecimal representation')) . '">'
            . '<i class="fas fa-rotate"></i></button>';
        break;

    case 'size-in-bytes':
        echo $hover(h($value));
        if (ctype_digit($value) && (int)$value > 1024) {
            echo ' <span class="text-muted small fw-normal">(' . h(CakeNumber::toReadableSize((int)$value)) . ')</span>';
        }
        break;

    case 'ip-dst|port':
    case 'ip-src|port':
    case 'hostname|port':
        $pieces = explode('|', $value, 2);
        $host = substr_count($pieces[0], ':') >= 2 ? '[' . $pieces[0] . ']' : $pieces[0];
        echo $hover(h($host . (isset($pieces[1]) ? ':' . $pieces[1] : '')));
        break;

    case 'domain':
    case 'hostname':
        echo $hover(h($value));
        if (stripos($value, 'xn--') !== false && function_exists('idn_to_utf8')) {
            $decoded = idn_to_utf8($value, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($decoded !== false && $decoded !== $value) {
                echo '<span class="d-block text-muted small fw-normal" title="'
                    . h(__('Internationalised (punycode) form decoded')) . '">'
                    . '<i class="fas fa-language me-1"></i>' . h($decoded) . '</span>';
            }
        }
        break;

    default:
        if (strpos($type, '|') !== false) {
            echo $lines(explode('|', $value));
        } else {
            echo $longText($value);
        }
}
