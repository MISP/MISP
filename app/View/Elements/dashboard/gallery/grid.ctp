<?php
/**
 * Widget gallery — outer shell template (PRD §5.7 / §5.8).
 *
 * Inert until the JS-wired "+ Add widget" flow clones it into the
 * configure side panel body. The element ships two HTML5 <template>
 * fragments:
 *
 *   1. #misp-gallery-template — outer shell with search input, live
 *      counter, scrollable body (where per-category sections land),
 *      and an empty-state message.
 *   2. #misp-gallery-category-template — per-category section the
 *      gallery JS clones once per non-empty bucket. Houses the
 *      category heading + a grid container that the card template
 *      (Elements/dashboard/gallery/card.ctp) populates.
 *
 * Theme override surface: this element is theme-neutral because the
 * gallery renders inside `.misp-configure-panel`, which itself is
 * served by the default index.ctp under both default and Overmind
 * themes (per the wrapper.ctp mirror's own comment — chrome is
 * theme-neutral; styling differences live in the per-theme CSS).
 * Overmind-specific gallery styling, if ever needed, should override
 * the `.misp-gallery-*` CSS classes rather than fork this markup.
 *
 * §8.5 stable hook contract — JS depends on these attributes:
 *   data-misp-gallery-template          — outer shell template
 *   data-misp-gallery-root              — instantiated shell root
 *   data-misp-gallery-search            — search input
 *   data-misp-gallery-counter           — "N of M" live count
 *   data-misp-gallery-body              — scrollable section container
 *   data-misp-gallery-empty             — no-match message
 *   data-misp-gallery-category-template — per-category section template
 *   data-misp-gallery-category          — instantiated category section
 *   data-misp-gallery-category-key      — bucket key (status/events/…)
 *   data-misp-gallery-category-heading  — heading text node
 *   data-misp-gallery-category-grid     — card grid container
 */
?>
<template id="misp-gallery-template" data-misp-gallery-template>
    <div class="misp-gallery" data-misp-gallery-root>
        <header class="misp-gallery-header">
            <label class="misp-gallery-search-label">
                <span class="visually-hidden"><?= __('Search widgets') ?></span>
                <input type="search"
                       class="misp-gallery-search"
                       data-misp-gallery-search
                       placeholder="<?= __('Search widgets…') ?>"
                       autocomplete="off"
                       spellcheck="false" />
            </label>
            <span class="misp-gallery-counter"
                  data-misp-gallery-counter
                  aria-live="polite"></span>
        </header>
        <div class="misp-gallery-body" data-misp-gallery-body></div>
        <p class="misp-gallery-empty"
           data-misp-gallery-empty
           hidden><?= __('No widgets match your search.') ?></p>
    </div>
</template>
<template id="misp-gallery-category-template" data-misp-gallery-category-template>
    <section class="misp-gallery-category"
             data-misp-gallery-category
             data-misp-gallery-category-key="">
        <h3 class="misp-gallery-category-heading"
            data-misp-gallery-category-heading></h3>
        <div class="misp-gallery-category-grid"
             data-misp-gallery-category-grid></div>
    </section>
</template>
