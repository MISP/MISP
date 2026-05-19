<?php
/**
 * Widget gallery — single-card template (PRD §5.7 / §5.8).
 *
 * Inert HTML5 <template>. The gallery JS clones one instance per
 * widget entry returned by `GET /dashboards/widgets` and populates
 * the title / description / category / size meta + the thumbnail
 * via the documented attribute hooks. The card root is a <button>
 * so Enter / Space activate the Add Widget flow (keyboard reach
 * per DD-08).
 *
 * The thumbnail container ships empty; the JS toggles its contents
 * to either an <img> (when the widget declares `$thumbnail` and the
 * URL resolves) or a category-shaped fallback glyph (otherwise).
 * Avoids loading 38 thumbnail URLs that don't exist today (no
 * widget declares `$thumbnail` in-tree).
 *
 * Theme override surface: card visual styling lives entirely in
 * `.misp-gallery-card*` CSS classes — themes restyle by overriding
 * those classes in their per-theme stylesheet. Do not fork this
 * markup unless the structure itself (button vs. div, meta items,
 * grid arrangement) needs to change.
 *
 * §8.5 stable hook contract — JS depends on these attributes:
 *   data-misp-gallery-card-template     — outer card template
 *   data-misp-gallery-card              — instantiated card root
 *   data-widget-name                    — class name (for Add flow)
 *   data-widget-category                — bucket (status/events/…)
 *   data-widget-default-w               — default grid width cells
 *   data-widget-default-h               — default grid height cells
 *   data-widget-render                  — render kind (SimpleList/…)
 *   data-misp-gallery-card-thumbnail    — thumbnail slot
 *   data-misp-gallery-card-title        — title text node
 *   data-misp-gallery-card-description  — description text node
 *   data-misp-gallery-card-meta         — meta list
 *   data-misp-gallery-card-category     — category meta item
 *   data-misp-gallery-card-size         — size meta item
 */
?>
<template id="misp-gallery-card-template" data-misp-gallery-card-template>
    <button type="button"
            class="misp-gallery-card"
            data-misp-gallery-card
            data-widget-name=""
            data-widget-category=""
            data-widget-default-w=""
            data-widget-default-h=""
            data-widget-render="">
        <span class="misp-gallery-card-thumbnail"
              data-misp-gallery-card-thumbnail
              aria-hidden="true"></span>
        <span class="misp-gallery-card-body">
            <span class="misp-gallery-card-title"
                  data-misp-gallery-card-title></span>
            <span class="misp-gallery-card-description"
                  data-misp-gallery-card-description></span>
            <span class="misp-gallery-card-meta"
                  data-misp-gallery-card-meta>
                <span class="misp-gallery-card-category"
                      data-misp-gallery-card-category></span>
                <span class="misp-gallery-card-size"
                      data-misp-gallery-card-size></span>
            </span>
        </span>
    </button>
</template>
