<?php
/**
 * Each account found, and each breach the identifier appears in.
 *
 * The creation date is the column worth having on the first table: an
 * identifier with accounts created across six years reads differently
 * from one whose accounts were all created in the same week.
 *
 * **The breach table is capped and says so.** A breach service can
 * return two hundred records for one address — 214 was measured — and
 * a table that long is not read, it is scrolled past. Newest first,
 * because recency is what a reader is deciding on, and the count of
 * what was left out is stated rather than the list quietly ending.
 *
 * **What was exposed is the column the table exists for.** *Which
 * breaches* is a list of names a reader mostly cannot act on; *were
 * passwords in any of them* is the question, and it is answered per
 * row rather than only in the summary so that the reader can see which
 * breach to go and read about.
 *
 * Each table draws only where there is something in it, so an address
 * with breaches and no accounts does not open with an empty header row.
 *
 * @var array $data
 */
$cap = 25;
$breaches = $data['breaches'];
$shown = array_slice($breaches, 0, $cap);
$hidden = count($breaches) - count($shown);
?>
<div class="vp-rf vp-rf-acct">
    <?php if (!empty($data['accounts'])): ?>
        <table class="table table-sm vp-rf-table">
            <thead>
                <tr>
                    <th scope="col"><?= h(__('Platform')) ?></th>
                    <th scope="col"><?= h(__('Handle')) ?></th>
                    <th scope="col"><?= h(__('Display name')) ?></th>
                    <th scope="col"><?= h(__('Created')) ?></th>
                    <th scope="col"><?= h(__('Last seen')) ?></th>
                    <th scope="col"><?= h(__('Source')) ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($data['accounts'] as $account): ?>
                    <tr>
                        <td><?= h($account['platform'] === null
                            ? '—' : $account['platform']) ?></td>
                        <td class="font-monospace"><?php
                            if ($account['link'] !== null): ?>
                            <a href="<?= h($account['link']) ?>"
                               rel="noreferrer noopener"
                               target="_blank"><?= h((string)
                                $account['handle']) ?></a>
                        <?php else: ?>
                            <?= h($account['handle'] === null
                                ? '—' : $account['handle']) ?>
                        <?php endif; ?></td>
                        <td><?= h($account['display'] === null
                            ? '—' : $account['display']) ?></td>
                        <td><?= h($account['created'] === null
                            ? '—'
                            : date('Y-m-d', $account['created'])) ?></td>
                        <td><?= h($account['last_login'] === null
                            ? '—'
                            : date('Y-m-d',
                                $account['last_login'])) ?></td>
                        <td class="font-monospace vp-rf-dim"><?=
                            $this->element('Values/Renderers/source_cell',
                                array('sources' => $account['sources'])
                            ) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <?php if (!empty($breaches)): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <span class="vp-rf-key"><?= h(sprintf(
                    __n('%s breach', '%s breaches', count($breaches)),
                    number_format(count($breaches))
                )) ?></span>
                <?php if ($data['first_breach'] !== null): ?>
                    <span class="vp-rf-dim"><?= h(sprintf(
                        __('%s to %s'),
                        date('Y', $data['first_breach']),
                        date('Y', $data['last_breach'])
                    )) ?></span>
                <?php endif; ?>
                <?php if ($data['passwords']): ?>
                    <span class="vp-rw-split"><?=
                        h(__('passwords exposed')) ?></span>
                <?php endif; ?>
            </div>
            <?php if (!empty($data['exposed'])): ?>
                <div class="vp-rf-dim"><?= h(sprintf(
                    __('Exposed across all of them: %s'),
                    implode(', ', $data['exposed'])
                )) ?></div>
            <?php endif; ?>
        </div>
        <table class="table table-sm vp-rf-table">
            <thead>
                <tr>
                    <th scope="col"><?= h(__('Breach')) ?></th>
                    <th scope="col"><?= h(__('Domain')) ?></th>
                    <th scope="col"><?= h(__('When')) ?></th>
                    <th scope="col"><?= h(__('Exposed')) ?></th>
                    <th scope="col" class="text-end"><?=
                        h(__('Accounts')) ?></th>
                    <th scope="col"><?= h(__('Source')) ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($shown as $breach): ?>
                    <tr>
                        <td><?php if ($breach['link'] !== null): ?>
                            <a href="<?= h($breach['link']) ?>"
                               rel="noreferrer noopener"
                               target="_blank"><?= h($breach['title']
                                ?? $breach['name']) ?></a>
                        <?php else: ?>
                            <?= h($breach['title']
                                ?? $breach['name']) ?>
                        <?php endif; ?><?php
                        /*
                         * Only an explicit denial is drawn. A service
                         * that said nothing about verification has not
                         * said the breach is unverified.
                         */
                        if ($breach['verified'] === false): ?><span
                            class="vp-rf-dim"> <?=
                            h(__('(unverified)')) ?></span><?php
                        endif; ?></td>
                        <td class="font-monospace"><?=
                            h($breach['domain'] === null
                                ? '—' : $breach['domain']) ?></td>
                        <td><?= h($breach['at'] === null
                            ? '—' : date('Y-m-d', $breach['at'])) ?></td>
                        <td><?php
                            $classes = $breach['classes'];
                            $first = array_slice($classes, 0, 4);
                            $rest = count($classes) - count($first);
                            echo h(empty($first)
                                ? '—' : implode(', ', $first));
                            if ($rest > 0): ?><span
                                class="vp-rf-dim"><?= h(sprintf(
                                    ' +%d', $rest
                                )) ?></span><?php endif; ?></td>
                        <td class="text-end"><?=
                            h($breach['accounts'] === null ? '—'
                                : number_format(
                                    $breach['accounts']
                                )) ?></td>
                        <td class="font-monospace vp-rf-dim"><?=
                            $this->element('Values/Renderers/source_cell',
                                array('sources' => $breach['sources'])
                            ) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php if ($hidden > 0): ?>
            <div class="vp-rf-dim"><?= h(sprintf(
                __n(
                    '%s more breach, not shown',
                    '%s more breaches, not shown',
                    $hidden
                ),
                number_format($hidden)
            )) ?></div>
        <?php endif; ?>
    <?php endif; ?>
</div>
