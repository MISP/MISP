<?php
App::uses('AppHelper', 'View/Helper');
App::uses('TagChipTool', 'Tools');
App::uses('GalaxyColour', 'Tools');
App::uses('FontAwesomeHelper', 'View/Helper');

/**
 * Renders tags as chips: the path on a first row and the leaf on a second,
 * or both on one row for a lone tag when asked. Two or more tags of a collection sharing a namespace fuse into a
 * block that prints the namespace once, each member keeping its predicate.
 * Colour means taxonomy: a taxonomy whose declared palette tells its
 * values apart (TLP, PAP) keeps its colours, every other one gets a hue
 * derived from its namespace. Galaxy clusters wear the same chip with their
 * galaxy in the namespace's place. Styles live in css/tag-chips.css.
 */
class TagChipHelper extends AppHelper
{
    /** @var string[]|null */
    private $semantic = null;

    /**
     * @param array $tags rows shaped as rich_tag accepts them
     * @param array $options
     *   scope, id          what the tags hang off, for the edit affordances
     *   searchUrl          link prefix, '' for no link
     *   href               callable(tag row): ?string, overrides searchUrl
     *   prefix             callable(tag row): string, HTML ahead of the chip
     *   suffix             callable(tag row): string, HTML after the chip
     *   unitClass          callable(tag row): string, extra class on the chip's unit
     *   canModifyAll       may remove any tag
     *   canModifyLocal     may remove local tags
     *   display            'full' (default), 'leaf' or 'swatch'
     *   inline             a lone tag keeps its leaf on the path's row,
     *                      unboxed (default false)
     *   group              fuse shared namespaces into blocks (default true)
     *   minGroup           members before a namespace earns a block (2)
     *   wideAt             members before a block takes its own line (8)
     *   track              column track width in px for a wide block
     *   fold               members above which a block folds into a strip
     *                      that lists them on hover (null: never)
     *   limit              units shown before a "+N" toggle (null: all);
     *                      a block or a strip is one unit
     *   class              extra class on the root
     * @return string
     */
    public function collection(array $tags, array $options = [])
    {
        $options += [
            'display' => 'full',
            'group' => true,
            'minGroup' => 2,
            'wideAt' => 8,
            'track' => null,
            'class' => '',
        ];
        return $this->renderRows($this->normalise($tags), $options);
    }

    /**
     * Galaxy clusters as chips: the galaxy takes the namespace's place, so the
     * clusters of one galaxy fuse into a block, and the galaxy keeps the
     * GalaxyColour hue its own pages carry.
     *
     * @param array $clusters flat rows: value, galaxy (name), and optionally
     *   id, galaxy_id, icon, tag_id, local, relationship_type, description;
     *   a GalaxyCluster row with its Galaxy attached is read too
     * @param array $options as collection(); href and prefix get the flat row
     * @return string
     */
    public function clusters(array $clusters, array $options = [])
    {
        $options += [
            'display' => 'full',
            'group' => true,
            'minGroup' => 2,
            'wideAt' => 8,
            'track' => null,
            'class' => '',
        ];
        $rows = [];
        foreach ($clusters as $cluster) {
            $row = $this->clusterRow($cluster);
            if ($row !== null) {
                $rows[] = $row;
            }
        }
        return $this->renderRows($rows, $options);
    }

    /**
     * A single cluster, never grouped.
     *
     * @param array $cluster as clusters()
     * @param array $options as collection()
     * @return string
     */
    public function cluster(array $cluster, array $options = [])
    {
        $options += ['display' => 'full', 'class' => ''];
        $row = $this->clusterRow($cluster);
        if ($row === null) {
            return '';
        }
        return $this->wrap($this->renderChip($row, 'flow', $options), $options);
    }

    /**
     * Tags or clusters as the reference lists a folded block opens onto: one
     * list per namespace or galaxy, whatever its size, in order of appearance.
     *
     * @param array $tags as collection()
     * @param array $clusters as clusters()
     * @param array $options ownColour: each tag row carries its tag's own
     *   colour, and a list whose tags share one takes it, as tag chips
     *   drawn outside this helper do
     * @return string
     */
    public function lists(array $tags, array $clusters = [], array $options = [])
    {
        $rows = $this->normalise($tags);
        foreach ($clusters as $cluster) {
            $row = $this->clusterRow($cluster);
            if ($row !== null) {
                $rows[] = $row;
            }
        }
        $groups = [];
        foreach ($rows as $row) {
            $namespace = $row['parsed']['namespace'];
            $key = isset($row['groupKey'])
                ? "\2" . $row['groupKey']
                : "\1" . mb_strtolower((string)$namespace);
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'namespace' => $namespace ?? __('Tags'),
                    'galaxy' => $row['galaxy'] ?? null,
                    'rows' => [],
                ];
            }
            $groups[$key]['rows'][] = $row;
        }
        $out = '';
        foreach ($groups as $group) {
            $first = $group['rows'][0];
            $style = sprintf('--hg-h:%d;--hg-s:62%%', $first['hue'] ?? TagChipTool::hue($group['namespace']));
            if (!empty($options['ownColour']) && !isset($first['hue'])) {
                $group['ownColour'] = true;
                $colours = array_unique(array_map(function ($row) {
                    return strtolower((string)$row['tag']['Tag']['colour']);
                }, $group['rows']));
                if (count($colours) === 1 && $this->isHex(reset($colours))) {
                    $style .= ';--hg-c:' . reset($colours);
                }
            }
            $out .= $this->renderCard($group, $style, $this->icon($first));
        }
        return $out;
    }

    private function renderRows(array $rows, array $options)
    {
        if (empty($rows)) {
            return '';
        }
        $grouping = $options['group'] && $options['display'] === 'full';

        $groups = [];
        foreach ($rows as $row) {
            $p = $row['parsed'];
            if ($p['namespace'] === null || !$grouping) {
                $key = "\0" . count($groups);
            } elseif (isset($row['groupKey'])) {
                $key = "\2" . $row['groupKey'];
            } else {
                $key = "\1" . mb_strtolower($p['namespace']);
            }
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'namespace' => $p['namespace'],
                    'galaxy' => $row['galaxy'] ?? null,
                    'rows' => [],
                ];
            }
            $groups[$key]['rows'][] = $row;
        }

        $units = [];
        foreach ($groups as $group) {
            $count = count($group['rows']);
            if ($grouping && $group['namespace'] !== null && $count >= $options['minGroup']) {
                $units[] = !empty($options['fold']) && $count > $options['fold']
                    ? $this->renderFold($group)
                    : $this->renderGroup($group, $options);
            } else {
                foreach ($group['rows'] as $row) {
                    $units[] = $this->renderChip($row, 'flow', $options);
                }
            }
        }

        $limit = (int)($options['limit'] ?? 0);
        $hidden = $limit > 0 ? count($units) - $limit : 0;
        if ($hidden <= 0) {
            return $this->wrap(implode('', $units), $options);
        }
        $body = implode('', array_slice($units, 0, $limit));
        foreach (array_slice($units, $limit) as $unit) {
            $body .= '<span class="hg-extra">' . $unit . '</span>';
        }
        $body .= sprintf(
            '<button type="button" class="hg-overflow badge text-bg-secondary noPrint" data-hidden="%d" aria-expanded="false" title="%s">+%d</button>',
            $hidden,
            __('Show %s more', $hidden),
            $hidden
        );
        return $this->wrap($body, $options);
    }

    /**
     * A single tag, never grouped.
     *
     * @param array $tag
     * @param array $options as collection()
     * @return string
     */
    public function chip(array $tag, array $options = [])
    {
        $options += ['display' => 'full', 'class' => ''];
        $rows = $this->normalise([$tag]);
        if (empty($rows)) {
            return '';
        }
        return $this->wrap($this->renderChip($rows[0], 'flow', $options), $options);
    }

    /**
     * Maps the legacy tag_display_style (0 colour only, 1 full name, 2 value
     * only) onto a display mode.
     *
     * @param mixed $style
     * @return string
     */
    public function displayFromStyle($style)
    {
        if ($style === 0 || $style === '0') {
            return 'swatch';
        }
        if ((int)$style === 2) {
            return 'leaf';
        }
        return 'full';
    }

    /**
     * @return string[] lowercased namespaces whose declared colours are kept
     */
    public function semanticNamespaces()
    {
        if ($this->semantic === null) {
            try {
                $this->semantic = ClassRegistry::init('Taxonomy')->semanticPaletteNamespaces();
            } catch (Exception $e) {
                $this->semantic = [];
            }
        }
        return $this->semantic;
    }

    /**
     * Hue and saturation for a tag, as CSS custom property values, and the
     * declared colour when the tag's taxonomy keeps it.
     *
     * @param array $parsed
     * @param string $colour
     * @return array{0: int, 1: string, 2: ?string}
     */
    private function hueOf(array $parsed, $colour)
    {
        if ($parsed['namespace'] === null) {
            return [0, '0%', null];
        }
        if (in_array(mb_strtolower($parsed['namespace']), $this->semanticNamespaces(), true)) {
            if (!preg_match('/^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$/', (string)$colour)) {
                return [0, '0%', null];
            }
            // A grey (tlp:clear is #ffffff) keeps its colour but has no hue
            $declared = TagChipTool::hueSat($colour);
            return [$declared['h'], $declared['s'] < 15 ? '0%' : '62%', strtolower($colour)];
        }
        return [TagChipTool::hue($parsed['namespace']), '62%', null];
    }

    /**
     * @param array $cluster
     * @return array|null a row as normalise() builds it, plus the cluster's
     *                    own hue, icon, link, title and grouping
     */
    private function clusterRow(array $cluster)
    {
        if (isset($cluster['GalaxyCluster']['value'])) {
            $galaxy = $cluster['Galaxy'] ?? $cluster['GalaxyCluster']['Galaxy'] ?? [];
            $cluster = $cluster['GalaxyCluster'];
            $cluster['Galaxy'] = $galaxy;
        }
        if (isset($cluster['Galaxy']) && is_array($cluster['Galaxy'])) {
            $cluster += [
                'galaxy' => $cluster['Galaxy']['name'] ?? '',
                'galaxy_id' => $cluster['Galaxy']['id'] ?? null,
                'icon' => $cluster['Galaxy']['icon'] ?? null,
            ];
        }
        $value = trim((string)($cluster['value'] ?? ''));
        if ($value === '') {
            return null;
        }
        $galaxy = trim((string)($cluster['galaxy'] ?? ''));
        $id = (int)($cluster['id'] ?? 0);
        $galaxyId = (int)($cluster['galaxy_id'] ?? 0);

        $description = trim((string)($cluster['description'] ?? ''));
        if (mb_strlen($description) > 300) {
            $description = rtrim(mb_substr($description, 0, 300)) . '…';
        }

        return [
            'tag' => [
                'Tag' => [
                    'id' => $cluster['tag_id'] ?? null,
                    'name' => $value,
                    'colour' => null,
                ],
                'local' => !empty($cluster['local']),
                'relationship_type' => $cluster['relationship_type'] ?? null,
            ],
            'parsed' => [
                'raw' => $value,
                'namespace' => $galaxy === '' ? null : $galaxy,
                'path' => [],
                'above' => [],
                'value' => $value,
                'leaf' => $value,
            ],
            'source' => $cluster,
            'hue' => GalaxyColour::hue($galaxy),
            'icon' => empty($cluster['icon']) ? null : (string)$cluster['icon'],
            'href' => $id ? $this->baseurl() . '/galaxy_clusters/view/' . $id : null,
            'title' => $galaxy === '' ? $value : $galaxy . ' › ' . $value,
            'note' => $description,
            'groupKey' => $galaxyId ?: mb_strtolower($galaxy),
            'galaxy' => [
                'name' => $galaxy,
                'href' => $galaxyId ? $this->baseurl() . '/galaxies/view/' . $galaxyId : null,
            ],
            'unit' => sprintf(
                'data-cluster-item data-cluster-name="%s" data-galaxy-name="%s"%s',
                h(mb_strtolower($value)),
                h(mb_strtolower($galaxy)),
                $id ? sprintf(' data-cluster-id="%d"', $id) : ''
            ),
        ];
    }

    private function icon(array $row)
    {
        if (empty($row['icon'])) {
            return '';
        }
        return sprintf(
            '<i class="hg-icon %s fa-%s" aria-hidden="true"></i>',
            FontAwesomeHelper::findNamespace($row['icon']),
            h($row['icon'])
        );
    }

    private function normalise(array $tags)
    {
        $rows = [];
        foreach ($tags as $tag) {
            if (empty($tag['Tag'])) {
                $tag['Tag'] = $tag;
            }
            if (!isset($tag['Tag']['name']) || trim($tag['Tag']['name']) === '') {
                continue;
            }
            if (empty($tag['Tag']['colour'])) {
                $tag['Tag']['colour'] = '#0088cc';
            }
            $rows[] = [
                'tag' => $tag,
                'parsed' => TagChipTool::parse($tag['Tag']['name']),
            ];
        }
        return $rows;
    }

    private function wrap($body, array $options)
    {
        $class = 'hinge-tags';
        if (!empty($options['class'])) {
            $class .= ' ' . $options['class'];
        }
        return sprintf('<span class="%s">%s</span>', h($class), $body);
    }

    /**
     * @param array $row
     * @param string $mode 'flow' stands alone; 'member' sits in a group
     *                     block whose header already carries the namespace
     * @param array $options
     * @return string
     */
    private function renderChip(array $row, $mode, array $options)
    {
        $tag = $row['tag'];
        $p = $row['parsed'];
        $display = $options['display'] ?? 'full';
        $isLocal = !empty($tag['local']);
        $rel = isset($tag['relationship_type']) && $tag['relationship_type'] !== ''
            ? $tag['relationship_type']
            : null;
        $member = $mode === 'member';
        // A free-text tag has no ancestry, and a member's namespace is
        // already in the block's header
        $showPath = $display === 'full'
            && ($member ? !empty($p['above']) : $p['namespace'] !== null);
        $stacked = $display !== 'swatch' && ($showPath || $rel);
        $inline = $stacked && !empty($options['inline']) && !$member;

        $nv = $tag['Tag']['numerical_value'] ?? null;
        $hasNv = $nv !== null && $nv !== '' && is_numeric($nv) && $display !== 'swatch';
        $nv = $hasNv ? $nv + 0 : null;
        $over = $hasNv && ($nv > 100 || $nv < 0);

        list($hue, $sat, $declared) = isset($row['hue'])
            ? [$row['hue'], '62%', null]
            : $this->hueOf($p, $tag['Tag']['colour']);

        $classes = ['hg-chip'];
        if ($isLocal) {
            $classes[] = 'is-local';
        }
        if ($display === 'swatch') {
            $classes[] = 'is-swatch';
        } elseif (!$stacked) {
            $classes[] = $member || $display !== 'full' ? 'is-tight' : 'is-single';
        } elseif ($inline) {
            $classes[] = 'is-inline';
        } elseif (!$member) {
            $classes[] = 'is-stacked';
        }
        if ($hasNv) {
            $classes[] = 'has-meter';
        }
        if ($declared !== null) {
            $classes[] = 'has-colour';
            if ($sat === '0%') {
                $classes[] = 'is-neutral';
            }
        }
        $inner = '';
        if ($display !== 'swatch') {
            if ($stacked) {
                $rail = '';
                if ($rel) {
                    $rail .= sprintf(
                        '<span class="hg-rel" title="%s">%s</span>',
                        h(__('Relationship: %s', $rel)),
                        h($rel)
                    );
                }
                if ($showPath) {
                    $segs = $p['above'];
                    if ($member) {
                        $path = h(array_shift($segs));
                    } else {
                        $path = $this->icon($row)
                            . sprintf('<b class="hg-ns">%s</b>', h($p['namespace']));
                    }
                    foreach ($segs as $seg) {
                        $path .= '<i class="hg-sep">&rsaquo;</i>' . h($seg);
                    }
                    $rail .= sprintf('<span class="hg-path">%s</span>', $path);
                }
                if ($hasNv && !$inline) {
                    $rail .= $this->numeral($nv, $over);
                }
                $inner .= sprintf('<span class="hg-rail">%s</span>', $rail);
            }

            $tail = sprintf('<span class="hg-leaf">%s</span>', h($p['leaf']));
            if ($hasNv && (!$stacked || $inline)) {
                $tail .= $this->numeral($nv, $over);
            }
            if ($isLocal) {
                $tail .= sprintf(
                    '<span class="hg-flag" title="%s">%s</span>',
                    isset($row['galaxy']) ? __('Local cluster') : __('Local tag'),
                    __('local')
                );
            }
            $inner .= sprintf('<span class="hg-tail">%s</span>', $tail);
            if ($hasNv) {
                $inner .= sprintf(
                    '<span class="hg-meter%s" aria-hidden="true"><i style="width:%d%%"></i></span>',
                    $over ? ' is-over' : '',
                    $over ? 100 : max(0, min(100, (int)round($nv)))
                );
            }
        }

        $title = $this->titleOf($row);
        $attrs = sprintf(
            'class="%s" style="--hg-h:%d;--hg-s:%s%s" title="%s"',
            implode(' ', $classes),
            $hue,
            $sat,
            $declared === null ? '' : ';--hg-c:' . $declared,
            h($title)
        );
        if ($display === 'swatch') {
            $attrs .= sprintf(' aria-label="%s"', h($title));
        }
        $tagId = isset($tag['Tag']['id']) ? (int)$tag['Tag']['id'] : 0;
        $searchUrl = $options['searchUrl'] ?? '/events/index/searchtag:';
        $source = $row['source'] ?? $tag;
        $href = null;
        if (isset($options['href']) && is_callable($options['href'])) {
            $href = $options['href']($source);
        } elseif (array_key_exists('href', $row)) {
            $href = $row['href'];
        } elseif ($tagId && $searchUrl !== '' && $searchUrl !== false) {
            $href = $this->baseurl() . $searchUrl . $tagId;
        }
        if ($tagId) {
            $attrs .= sprintf(' data-tag-id="%d"', $tagId);
        }
        if ($href !== null && $href !== '') {
            $out = sprintf('<a href="%s" %s>%s</a>', h($href), $attrs, $inner);
        } else {
            $out = sprintf('<span %s>%s</span>', $attrs, $inner);
        }

        if (!empty($options['canModifyAll']) || (!empty($options['canModifyLocal']) && $isLocal)) {
            $scope = $options['scope'] ?? 'event';
            if (!empty($tag['id'])) {
                $out .= sprintf(
                    '<a class="hg-act noPrint modal-open" href="%s" title="%s" aria-label="%s" role="button" tabindex="0">'
                        . '<i class="fas fa-project-diagram"></i></a>',
                    h(sprintf('%s/tags/modifyTagRelationship/%s/%s', $this->baseurl(), $scope, $tag['id'])),
                    __('Modify Tag Relationship'),
                    __('Modify relationship for tag %s', h($p['raw']))
                );
            }
            $out .= sprintf(
                '<button type="button" class="hg-act noPrint" title="%s" aria-label="%s" onclick="%s">&times;</button>',
                __('Remove tag'),
                __('Remove tag %s', h($p['raw'])),
                h(sprintf(
                    "removeObjectTagPopup(this, '%s', %s, %s)",
                    $scope,
                    (int)($options['id'] ?? 0),
                    $tagId
                ))
            );
        }
        if (isset($options['prefix']) && is_callable($options['prefix'])) {
            $out = $options['prefix']($source) . $out;
        }
        if (isset($options['suffix']) && is_callable($options['suffix'])) {
            $out .= $options['suffix']($source);
        }
        $unitClass = isset($options['unitClass']) && is_callable($options['unitClass'])
            ? trim((string)$options['unitClass']($source))
            : '';
        return sprintf(
            '<span class="hg-unit%s" %s>%s</span>',
            $unitClass === '' ? '' : ' ' . h($unitClass),
            $row['unit'] ?? sprintf('data-tag-item data-tag-name="%s"', h(mb_strtolower($p['raw']))),
            $out
        );
    }

    private function renderGroup(array $group, array $options)
    {
        $count = count($group['rows']);
        $classes = ['hg-group'];
        if ($count >= $options['wideAt']) {
            $classes[] = 'is-wide';
        }
        $first = $group['rows'][0];
        $galaxy = $group['galaxy'];
        // A hand-picked palette keeps a bar on every member, because those
        // bars differ; a derived one puts its single hue on the block.
        if ($galaxy === null && in_array(mb_strtolower($group['namespace']), $this->semanticNamespaces(), true)) {
            $classes[] = 'is-varied';
        }

        $head = $this->icon($first);
        if (!empty($galaxy['href'])) {
            $head .= sprintf(
                '<a class="hg-hns" href="%s" title="%s">%s</a>',
                h($galaxy['href']),
                __('View galaxy'),
                h($group['namespace'])
            );
        } else {
            $head .= sprintf('<b class="hg-hns">%s</b>', h($group['namespace']));
        }
        $head .= sprintf(
            '<span class="hg-count" title="%s">%d</span>',
            $galaxy === null
                ? __('%s tags share this namespace', $count)
                : __('%s clusters of this galaxy', $count),
            $count
        );

        $members = '';
        foreach ($group['rows'] as $row) {
            $members .= $this->renderChip($row, 'member', $options);
        }

        return sprintf(
            '<span class="%s" style="--hg-h:%d;--hg-s:62%%%s" title="%s"%s>'
                . '<span class="hg-head">%s</span><span class="hg-members">%s</span></span>',
            implode(' ', $classes),
            $first['hue'] ?? TagChipTool::hue($group['namespace']),
            empty($options['track']) ? '' : sprintf(';--hg-colw:%dpx', $options['track']),
            h($group['namespace']),
            $galaxy === null
                ? ''
                : sprintf(' data-galaxy-group data-galaxy-name="%s"', h(mb_strtolower($galaxy['name']))),
            $head,
            $members
        );
    }

    private function titleOf(array $row)
    {
        $tag = $row['tag'];
        $title = $row['title'] ?? $row['parsed']['raw'];
        if (isset($tag['relationship_type']) && $tag['relationship_type'] !== '') {
            $title = $tag['relationship_type'] . ': ' . $title;
        }
        if (!empty($tag['local'])) {
            $title .= ' (' . __('local') . ')';
        }
        if (!empty($row['note'])) {
            $title .= "\n\n" . $row['note'];
        }
        return $title;
    }

    /**
     * A block too big for a cell: one line holding the namespace, a tally of
     * one mark per member and the count. The members wait in a template that
     * tag-chips.js lifts into a popover on hover or focus.
     */
    private function renderFold(array $group)
    {
        $rows = $group['rows'];
        $count = count($rows);
        $galaxy = $group['galaxy'];
        $first = $rows[0];
        $varied = $galaxy === null
            && in_array(mb_strtolower($group['namespace']), $this->semanticNamespaces(), true);
        $style = sprintf('--hg-h:%d;--hg-s:62%%', $first['hue'] ?? TagChipTool::hue($group['namespace']));
        $icon = $this->icon($first);
        $label = $galaxy === null ? __('%s tags', $count) : __('%s clusters', $count);

        $marks = '';
        foreach (array_chunk(array_slice($rows, 0, 160), 40) as $chunk) {
            $marks .= '<span class="hg-mrow">';
            foreach ($chunk as $row) {
                $declared = $varied ? $this->hueOf($row['parsed'], $row['tag']['Tag']['colour'])[2] : null;
                $marks .= $declared === null ? '<i></i>' : sprintf('<i style="--hg-c:%s"></i>', $declared);
            }
            $marks .= '</span>';
        }
        if ($count > 160) {
            $marks .= '<span class="hg-marks-more">+</span>';
        }

        return sprintf(
            '<span class="hg-fold" style="%s"%s><button type="button" class="hg-strip" aria-haspopup="true" aria-expanded="false" aria-label="%s">'
                . '%s<b class="hg-hns">%s</b><span class="hg-marks" aria-hidden="true">%s</span><span class="hg-fold-n">%d</span>'
                . '</button><template>%s</template></span>',
            $style,
            $galaxy === null
                ? ''
                : sprintf(' data-galaxy-group data-galaxy-name="%s"', h(mb_strtolower($galaxy['name']))),
            h(__('%s: %s, show all', $group['namespace'], $label)),
            $icon,
            h($group['namespace']),
            $marks,
            $count,
            $this->renderCard($group, $style, $icon)
        );
    }

    /**
     * The folded members as a reference list, one per line. Values ending in
     * an id ("Name - T1588.004") sort by it and nest under their parent id;
     * the rest sort by predicate then value, members sharing a predicate
     * listed under it once.
     */
    private function renderCard(array $group, $style, $icon)
    {
        $items = [];
        $coded = 0;
        foreach ($group['rows'] as $i => $row) {
            $p = $row['parsed'];
            $nv = $row['tag']['Tag']['numerical_value'] ?? null;
            $item = [
                'i' => $i,
                'row' => $row,
                'name' => $p['leaf'],
                'code' => '',
                'right' => is_numeric($nv) ? (string)($nv + 0) : '',
                'path' => implode(' › ', $p['above']),
            ];
            if (preg_match('/^(.*\S)\s+-\s+(\S*\d\S*)$/u', $p['leaf'], $m)) {
                $item['name'] = $m[1];
                $item['code'] = $item['right'] = $m[2];
                $coded++;
            }
            $items[] = $item;
        }
        $byId = $coded > 1;
        usort($items, function ($a, $b) use ($byId) {
            if ($byId && ($a['code'] === '') !== ($b['code'] === '')) {
                return $a['code'] === '' ? 1 : -1;
            }
            return ($byId ? strnatcasecmp($a['code'], $b['code']) : 0)
                ?: strnatcasecmp($a['path'], $b['path'])
                ?: strnatcasecmp($a['name'], $b['name'])
                ?: $a['i'] - $b['i'];
        });

        $families = [];
        $codes = $byId ? array_flip(array_filter(array_column($items, 'code'))) : [];
        foreach ($items as $item) {
            $last = count($families) - 1;
            $dot = strrpos($item['code'], '.');
            $parent = $dot ? substr($item['code'], 0, $dot) : '';
            if ($parent !== '' && isset($codes[$parent]) && $last >= 0) {
                $item['parent'] = $parent;
                $families[$last]['items'][] = $item;
            } elseif ($item['path'] !== '' && $last >= 0 && $families[$last]['path'] === $item['path']) {
                $families[$last]['items'][] = $item;
            } else {
                $families[] = ['path' => $item['path'], 'items' => [$item]];
            }
        }

        $rels = array_unique(array_map(function ($item) {
            return (string)($item['row']['tag']['relationship_type'] ?? '');
        }, $items));
        $sharedRel = count($rels) === 1 ? reset($rels) : '';
        $nameWidth = 0;
        $rightWidth = 0;
        $list = '';
        foreach ($families as $family) {
            $headed = $family['path'] !== '' && count($family['items']) > 1;
            $list .= '<li class="hg-fam">';
            if ($headed) {
                $list .= sprintf('<div class="hg-fam-head">%s</div>', h($family['path']));
            }
            foreach ($family['items'] as $item) {
                $sub = $headed || isset($item['parent']);
                $prefix = !$headed && $item['path'] !== '' ? $item['path'] : '';
                $nameWidth = max($nameWidth, mb_strlen($prefix . $item['name']) + ($prefix === '' ? 0 : 1) + ($sub ? 2 : 0));
                $rightWidth = max($rightWidth, mb_strlen($item['right']));
                $tag = $item['row']['tag'];
                $rel = $sharedRel === '' ? (string)($tag['relationship_type'] ?? '') : '';
                $name = ($rel === '' ? '' : sprintf('<span class="hg-rel">%s</span> ', h($rel)))
                    . ($prefix === '' ? '' : sprintf('<span class="hg-row-path">%s</span> ', h($prefix)))
                    . h($item['name']);
                $right = h($item['right']);
                if (isset($item['parent'])) {
                    $right = sprintf('<span class="hg-code-up">%s</span>%s', h($item['parent']), h(substr($item['right'], strlen($item['parent']))));
                }
                $tagId = (int)($tag['Tag']['id'] ?? 0);
                $colour = (string)($tag['Tag']['colour'] ?? '');
                $list .= sprintf(
                    '<div class="hg-row%s" title="%s"%s%s><span class="hg-name">%s</span>%s%s</div>',
                    $sub ? ' is-sub' : '',
                    h($this->titleOf($item['row'])),
                    $tagId ? sprintf(' data-tag-id="%d"', $tagId) : '',
                    !empty($group['ownColour']) && $this->isHex($colour) ? sprintf(' style="--tc:%s"', strtolower($colour)) : '',
                    $name,
                    empty($tag['local']) ? '' : sprintf('<span class="hg-flag">%s</span>', __('local')),
                    $item['right'] === '' ? '' : sprintf('<span class="hg-lead"></span><code class="hg-code">%s</code>', $right)
                );
            }
            $list .= '</li>';
        }

        $count = count($items);
        return sprintf(
            '<div class="hinge-tags hg-card%s" style="%s"><div class="hg-card-head">%s%s<b class="hg-hns">%s</b><span class="hg-fold-n">%d</span>%s</div>'
                . '<ol class="hg-list" data-cols="%d" style="--hg-namew:%dch;--hg-codew:%dch">%s</ol></div>',
            empty($group['ownColour']) ? '' : ' is-own',
            $style,
            $sharedRel === '' ? '' : sprintf('<span class="hg-rel">%s</span>', h($sharedRel)),
            $icon,
            h($group['namespace']),
            $count,
            $byId ? sprintf('<span class="hg-card-note">%s</span>', __('by ID')) : '',
            $count > 24 ? 3 : ($count > 10 ? 2 : 1),
            min(44, max(12, $nameWidth)),
            $rightWidth,
            $list
        );
    }

    private function isHex($colour)
    {
        return (bool)preg_match('/^#[0-9a-f]{3}(?:[0-9a-f]{3})?$/i', (string)$colour);
    }

    private function numeral($nv, $over)
    {
        return sprintf(
            '<span class="hg-n%s" title="%s">%s</span>',
            $over ? ' is-over' : '',
            __('Numerical value: %s', h($nv)),
            h($over ? $nv . '↑' : $nv)
        );
    }

    private function baseurl()
    {
        return $this->_View->viewVars['baseurl'] ?? (string)Configure::read('MISP.baseurl');
    }
}
