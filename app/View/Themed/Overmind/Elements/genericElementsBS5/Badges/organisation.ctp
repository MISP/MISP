<?php
/*
 * An organisation as every index draws it (org-tile.css): its logo, or a
 * coloured monogram, with the reader's grade in the corner; its name beside,
 * linked to its local record if it has one; its description under the name
 * when asked for.
 *
 *   $org            array        id, uuid, name (and description)
 *   $orgName        string|null  shown instead of the org's name
 *   $orgTitle       string|null  the name's tooltip
 *   $orgDescription string|false 'line' (one truncated line), 'full', or false
 *   $orgSize        int          the tile's side in px, 24 by default
 *   $orgFit         bool         the name never shrinks
 *   $orgGrade       bool         false leaves the grade out
 */
$org = is_array($org ?? null) ? $org : [];
$name = (string)($orgName ?? ($org['name'] ?? ''));
if ($name === '') {
    echo '<span class="text-body-secondary">&mdash;</span>';
    return;
}
if (!isset($org['name'])) {
    $org['name'] = $name;
}
$size = (int)($orgSize ?? 24);
$target = empty($org['id']) ? null : $org['id'];

$grading = ($orgGrade ?? true) === false ? null : $this->OrgGrade->reading();
$badge = $grading ? $this->OrgGrade->badge($org, $grading) : '';

$description = '';
$mode = $orgDescription ?? false;
if ($mode && !empty($org['description'])) {
    $text = trim($org['description']);
    $description = sprintf(
        '<span class="org-id-desc%s" title="%s">%s</span>',
        $mode === 'full' ? ' is-full' : '',
        h($text),
        $mode === 'full' ? nl2br(h($text)) : h($text)
    );
}

$nameHtml = $target === null
    ? sprintf('<span class="org-id-name"%s>%s</span>', empty($orgTitle) ? '' : ' title="' . h($orgTitle) . '"', h($name))
    : sprintf(
        '<a class="org-id-name" href="%s"%s>%s</a>',
        h($baseurl . '/organisations/view/' . $target),
        empty($orgTitle) ? '' : ' title="' . h($orgTitle) . '"',
        h($name)
    );

$classes = 'org-id' . (empty($orgFit) ? '' : ' is-fit') . ($description === '' ? '' : ' has-desc');
$style = $size === 24 ? '' : sprintf(' style="--org-id-size:%dpx"', $size);

echo $badge === '' ? '' : $this->OrgGrade->config($grading);
printf(
    '<span class="%s"%s><span class="org-id-mark">%s%s</span><span class="org-id-text">%s%s</span></span>',
    $classes,
    $style,
    $this->EventIndex->orgTile($org, $size),
    $badge,
    $nameHtml,
    $description
);
