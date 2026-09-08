<?php

$total = count($relatedEvents);

$distMap = $this->DistributionLevel->all();
?>

<div data-related-count="<?= $total ?>">

<?php if ($total === 0): ?>

    <div class="d-flex flex-column align-items-center justify-content-center
                text-muted py-4">
        <i class="fas fa-link fa-2x mb-2 opacity-50"></i>
        <p class="mb-0 small fw-semibold">
            <?= __('No correlated events found.') ?>
        </p>
    </div>

<?php else: ?>

    <div class="d-flex flex-column">
    <?php foreach ($relatedEvents as $re):
        $ev      = $re['Event'];
        $evId    = (int)($ev['id'] ?? 0);
        $info    = h($ev['info'] ?? '');
        $date    = h($ev['date'] ?? '');
        $orgName = h($ev['Orgc']['name'] ?? $ev['Org']['name'] ?? '');
        $distId  = (int)($ev['distribution'] ?? 0);
        $dist    = $distMap[$distId] ?? $distMap[0];
        $corrCount = (int)($correlationCounts[$evId] ?? 0);
    ?>
        <a href="<?= h($baseurl) ?>/events/view2/<?= $evId ?>"
           class="d-flex align-items-start gap-3 px-3 py-2
                  text-decoration-none text-dark border-bottom
                  related-event-row"
           style="transition:background .15s;">

            <!-- Distribution badge -->
            <div class="rounded-2 d-flex align-items-center
                        justify-content-center flex-shrink-0 mt-1"
                 style="width:34px;height:34px;
                        background:<?= $dist['bg'] ?>;
                        border:1px solid <?= $dist['color'] ?>33;"
                 title="<?= h($dist['label']) ?>">
                <i class="<?= h($dist['icon']) ?>"
                   style="color:<?= $dist['color'] ?>;
                          font-size:.85rem;"></i>
            </div>

            <div class="flex-fill overflow-hidden">
                <!-- Event title -->
                <div class="fw-semibold text-truncate small lh-sm">
                    <?= $info ?>
                </div>
                <!-- Meta -->
                <div class="d-flex align-items-center gap-2 mt-1
                            flex-wrap">
                    <span class="text-muted"
                          style="font-size:.75rem;">
                        <?= $orgName ?>
                    </span>
                    <span class="text-muted"
                          style="font-size:.75rem;">·</span>
                    <time class="text-muted"
                          style="font-size:.75rem;">
                        <?= $date ?>
                    </time>
                </div>
            </div>

            <?php if ($corrCount > 0): ?>
            <!-- Correlation count badge -->
            <span class="badge rounded-pill flex-shrink-0 align-self-center"
                  style="background:#dbeafe;color:#1e40af;
                         font-size:.72rem;"
                  title="<?= __n(
                      '%s shared correlation',
                      '%s shared correlations',
                      $corrCount, $corrCount
                  ) ?>">
                <?= $corrCount ?>
            </span>
            <?php endif; ?>

        </a>
    <?php endforeach; ?>
    </div>

<?php endif; ?>

</div>

<style>
.related-event-row:hover { background: #f8fafc; }
</style>
