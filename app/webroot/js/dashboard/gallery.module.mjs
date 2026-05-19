/**
 * Widget gallery module (PRD §5.7 / §5.8).
 *
 * Opens the configure side panel in "gallery" mode: fetches the
 * widget catalogue from `/dashboards/widgets`, clones the dormant
 * <template> markup emitted by `Elements/dashboard/gallery/grid.ctp`
 * + `card.ctp` into the panel body, groups cards by `$category`
 * (PRD §5.7 bucket catalogue), wires a live search filter, and
 * dispatches an `onPick` callback when the user clicks a card.
 *
 * Browse-only at this commit — `onPick` is wired but its consumer
 * (the Add Widget flow) lands as the next progress-tracker task.
 *
 * Coupling with configure.module.mjs: this module piggybacks on the
 * configure side panel chrome (open/close transitions, backdrop, ✕,
 * Cancel, ESC). The panel's `hidden` attribute is the canonical
 * close signal — a MutationObserver on it triggers gallery state
 * cleanup so we don't have to win the close-listener race against
 * configure.module.mjs. Gallery and form modes are distinguished by
 * the `data-misp-configure-mode` attribute on the panel root; the
 * CSS layer can use the attribute to hide form-only chrome (the
 * footer Save/Cancel buttons aren't meaningful while browsing the
 * gallery).
 *
 * ESC handling: configure.module.mjs's existing ESC handler is
 * gated on its private `openTarget` (form-mode only), so gallery
 * mode needs its own ESC listener (added in init() below).
 */

const ATTR_PANEL           = 'data-misp-configure-root';
const ATTR_PANEL_BODY      = 'data-misp-configure-body';
const ATTR_PANEL_TITLE     = 'data-misp-configure-title';
const ATTR_PANEL_MODE      = 'data-misp-configure-mode';
const ATTR_BACKDROP        = 'data-misp-configure-backdrop';
const ATTR_BOARD_ROOT      = 'data-misp-board-root';
const ATTR_BOARD_WIDGETS_URL = 'data-misp-board-widgets-url';

const ATTR_GALLERY_TEMPLATE          = 'data-misp-gallery-template';
const ATTR_GALLERY_CARD_TEMPLATE     = 'data-misp-gallery-card-template';
const ATTR_GALLERY_CATEGORY_TEMPLATE = 'data-misp-gallery-category-template';
const ATTR_GALLERY_ROOT              = 'data-misp-gallery-root';
const ATTR_GALLERY_SEARCH            = 'data-misp-gallery-search';
const ATTR_GALLERY_COUNTER           = 'data-misp-gallery-counter';
const ATTR_GALLERY_BODY              = 'data-misp-gallery-body';
const ATTR_GALLERY_EMPTY             = 'data-misp-gallery-empty';
const ATTR_GALLERY_CATEGORY          = 'data-misp-gallery-category';
const ATTR_GALLERY_CATEGORY_KEY      = 'data-misp-gallery-category-key';
const ATTR_GALLERY_CATEGORY_HEADING  = 'data-misp-gallery-category-heading';
const ATTR_GALLERY_CATEGORY_GRID     = 'data-misp-gallery-category-grid';
const ATTR_GALLERY_CARD              = 'data-misp-gallery-card';
const ATTR_GALLERY_CARD_THUMBNAIL    = 'data-misp-gallery-card-thumbnail';
const ATTR_GALLERY_CARD_TITLE        = 'data-misp-gallery-card-title';
const ATTR_GALLERY_CARD_DESC         = 'data-misp-gallery-card-description';
const ATTR_GALLERY_CARD_CATEGORY     = 'data-misp-gallery-card-category';
const ATTR_GALLERY_CARD_SIZE         = 'data-misp-gallery-card-size';

const CATEGORY_LABELS = {
  status:  'Status',
  events:  'Events',
  tags:    'Tags',
  orgs:    'Organisations',
  system:  'System',
  custom:  'Custom',
  '':      'Uncategorised',
};
const CATEGORY_ORDER = ['status', 'events', 'tags', 'orgs', 'system', 'custom', ''];

let onPickCallback = null;
let totalCardCount = 0;

/**
 * Open the gallery inside the configure side panel. Fetches
 * `/dashboards/widgets`, populates the panel body, focuses the
 * search input. Resolves once the panel is visible — the fetch +
 * render happens in the background; the panel stays visually open
 * while waiting.
 *
 * @param {object} opts
 * @param {(widgetMeta: object) => void} [opts.onPick] Invoked when
 *        the user clicks a card. Receives a minimal widget meta
 *        object: { widget, category, width, height, render }.
 */
export async function openGallery(opts = {}) {
  const panel    = document.querySelector(`[${ATTR_PANEL}]`);
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  const body     = panel?.querySelector(`[${ATTR_PANEL_BODY}]`);
  const titleEl  = panel?.querySelector(`[${ATTR_PANEL_TITLE}]`);
  if (!panel || !backdrop || !body) {
    console.warn('[misp-dashboard] configure panel markup not found');
    return;
  }
  onPickCallback = opts.onPick || null;

  panel.setAttribute(ATTR_PANEL_MODE, 'gallery');
  if (titleEl) titleEl.textContent = 'Add widget';

  // Clone the gallery shell. The card / category subtemplates are
  // cloned per-entry during renderGallery().
  const shellTmpl = document.querySelector(`[${ATTR_GALLERY_TEMPLATE}]`);
  if (!shellTmpl || !shellTmpl.content) {
    console.warn('[misp-dashboard] gallery shell template not found');
    return;
  }
  body.replaceChildren(shellTmpl.content.cloneNode(true));

  // Pre-fetch placeholder: the gallery shell is visible immediately;
  // the cards land asynchronously as the fetch resolves.
  panel.removeAttribute('hidden');
  backdrop.removeAttribute('hidden');
  // Force a reflow so the .is-open transition animates from off-screen.
  void panel.offsetWidth;
  panel.classList.add('is-open');

  const boardRoot = document.querySelector(`[${ATTR_BOARD_ROOT}]`);
  const widgetsUrl = boardRoot?.getAttribute(ATTR_BOARD_WIDGETS_URL);
  if (!widgetsUrl) {
    console.warn('[misp-dashboard] no widgets-url attribute on board root');
    return;
  }
  let widgets = [];
  try {
    const resp = await fetch(widgetsUrl, {
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    widgets = await resp.json();
  } catch (err) {
    console.warn('[misp-dashboard] gallery widgets fetch failed', err);
    return;
  }
  if (panel.getAttribute(ATTR_PANEL_MODE) !== 'gallery') {
    // User closed the gallery before the fetch resolved.
    return;
  }
  renderGallery(panel, widgets);

  const searchInput = panel.querySelector(`[${ATTR_GALLERY_SEARCH}]`);
  if (searchInput) searchInput.focus();
}

/**
 * Close the gallery and hide the panel. Idempotent — calling when
 * already closed is a no-op. The MutationObserver in init() also
 * runs the state-cleanup branch when the panel is hidden by any
 * external close path (✕ button, backdrop click, the Cancel button
 * — all routed through configure.module.mjs's closeConfigure).
 */
export function closeGallery() {
  const panel    = document.querySelector(`[${ATTR_PANEL}]`);
  const backdrop = document.querySelector(`[${ATTR_BACKDROP}]`);
  if (!panel) return;
  panel.classList.remove('is-open');
  panel.setAttribute('hidden', '');
  if (backdrop) backdrop.setAttribute('hidden', '');
}

// ---- rendering ----

function renderGallery(panel, widgets) {
  const body = panel.querySelector(`[${ATTR_GALLERY_BODY}]`);
  if (!body) return;
  const categoryTmpl = document.querySelector(`[${ATTR_GALLERY_CATEGORY_TEMPLATE}]`);
  const cardTmpl     = document.querySelector(`[${ATTR_GALLERY_CARD_TEMPLATE}]`);
  if (!categoryTmpl || !cardTmpl) return;

  // Bucket by category.
  const buckets = new Map();
  for (const w of widgets) {
    const cat = (typeof w.category === 'string' && w.category) ? w.category : '';
    if (!buckets.has(cat)) buckets.set(cat, []);
    buckets.get(cat).push(w);
  }
  for (const arr of buckets.values()) {
    arr.sort((a, b) =>
      (a.title || a.widget || '').localeCompare(b.title || b.widget || ''));
  }

  body.replaceChildren();
  totalCardCount = 0;
  const rendered = new Set();
  for (const key of CATEGORY_ORDER) {
    if (!buckets.has(key)) continue;
    appendCategorySection(body, categoryTmpl, cardTmpl, key, buckets.get(key));
    rendered.add(key);
  }
  // Defensive: a custom user widget could declare a category that
  // isn't in the PRD catalogue; render those buckets at the end so
  // they're still discoverable.
  for (const key of buckets.keys()) {
    if (rendered.has(key)) continue;
    appendCategorySection(body, categoryTmpl, cardTmpl, key, buckets.get(key));
  }

  wireSearch(panel);
  updateCounter(panel);
}

function appendCategorySection(body, categoryTmpl, cardTmpl, key, widgets) {
  const node = categoryTmpl.content.cloneNode(true);
  const section = node.querySelector(`[${ATTR_GALLERY_CATEGORY}]`);
  if (!section) return;
  section.setAttribute(ATTR_GALLERY_CATEGORY_KEY, key);
  const heading = section.querySelector(`[${ATTR_GALLERY_CATEGORY_HEADING}]`);
  if (heading) heading.textContent = CATEGORY_LABELS[key] || key || 'Uncategorised';
  const grid = section.querySelector(`[${ATTR_GALLERY_CATEGORY_GRID}]`);
  if (grid) {
    for (const w of widgets) {
      const cardNode = cardTmpl.content.cloneNode(true);
      populateCard(cardNode, w);
      grid.appendChild(cardNode);
      totalCardCount += 1;
    }
  }
  body.appendChild(section);
}

function populateCard(cardNode, widget) {
  const card = cardNode.querySelector(`[${ATTR_GALLERY_CARD}]`);
  if (!card) return;
  card.setAttribute('data-widget-name', widget.widget || '');
  card.setAttribute('data-widget-category', widget.category || '');
  card.setAttribute('data-widget-default-w', String(widget.width || 1));
  card.setAttribute('data-widget-default-h', String(widget.height || 1));
  card.setAttribute('data-widget-render', widget.render || '');

  const titleEl = card.querySelector(`[${ATTR_GALLERY_CARD_TITLE}]`);
  if (titleEl) titleEl.textContent = widget.title || widget.widget || '';

  const descEl = card.querySelector(`[${ATTR_GALLERY_CARD_DESC}]`);
  if (descEl) descEl.textContent = widget.description || '';

  const catEl = card.querySelector(`[${ATTR_GALLERY_CARD_CATEGORY}]`);
  if (catEl) {
    catEl.textContent = CATEGORY_LABELS[widget.category]
      || widget.category || 'Uncategorised';
  }

  const sizeEl = card.querySelector(`[${ATTR_GALLERY_CARD_SIZE}]`);
  if (sizeEl) {
    sizeEl.textContent = `${widget.width || 1}×${widget.height || 1}`;
  }

  const thumbSlot = card.querySelector(`[${ATTR_GALLERY_CARD_THUMBNAIL}]`);
  if (thumbSlot && widget.thumbnail) {
    const img = document.createElement('img');
    img.src = widget.thumbnail;
    img.alt = '';
    thumbSlot.appendChild(img);
  }
}

// ---- search ----

function wireSearch(panel) {
  const input = panel.querySelector(`[${ATTR_GALLERY_SEARCH}]`);
  if (!input) return;
  input.addEventListener('input', () => {
    applySearch(panel, input.value);
  });
}

function applySearch(panel, query) {
  const q = (query || '').trim().toLowerCase();
  const cards = panel.querySelectorAll(`[${ATTR_GALLERY_CARD}]`);
  let visible = 0;
  for (const card of cards) {
    const name  = (card.getAttribute('data-widget-name')  || '').toLowerCase();
    const title = (card.querySelector(`[${ATTR_GALLERY_CARD_TITLE}]`)?.textContent || '').toLowerCase();
    const desc  = (card.querySelector(`[${ATTR_GALLERY_CARD_DESC}]`)?.textContent  || '').toLowerCase();
    const cat   = (card.getAttribute('data-widget-category') || '').toLowerCase();
    const match = !q
      || name.includes(q)
      || title.includes(q)
      || desc.includes(q)
      || cat.includes(q);
    card.hidden = !match;
    if (match) visible += 1;
  }
  // Collapse empty category sections so the user doesn't see an
  // empty heading sitting between two populated sections.
  const sections = panel.querySelectorAll(`[${ATTR_GALLERY_CATEGORY}]`);
  for (const section of sections) {
    const anyVisible = Array.from(
      section.querySelectorAll(`[${ATTR_GALLERY_CARD}]`)
    ).some(c => !c.hidden);
    section.hidden = !anyVisible;
  }
  updateCounter(panel, visible);
  const emptyEl = panel.querySelector(`[${ATTR_GALLERY_EMPTY}]`);
  if (emptyEl) emptyEl.hidden = visible !== 0;
}

function updateCounter(panel, visible = null) {
  const counter = panel.querySelector(`[${ATTR_GALLERY_COUNTER}]`);
  if (!counter) return;
  const v = visible === null ? totalCardCount : visible;
  counter.textContent = v === totalCardCount
    ? `${totalCardCount} widgets`
    : `${v} of ${totalCardCount}`;
}

// ---- init ----

function init() {
  const panel = document.querySelector(`[${ATTR_PANEL}]`);
  if (!panel) return;

  // ESC in gallery mode. configure.module.mjs's existing ESC
  // handler bails when its private `openTarget` is null, so the
  // gallery needs its own ESC route.
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (panel.getAttribute(ATTR_PANEL_MODE) !== 'gallery') return;
    e.preventDefault();
    closeGallery();
  });

  // Card click — delegated. configure.module.mjs's Cancel / ✕ click
  // listener also fires for any [data-misp-configure-action] click,
  // but the cancel action doesn't bubble out (preventDefault stops
  // it), so a click on a [data-misp-gallery-card] inside the same
  // panel reaches this listener without interference.
  panel.addEventListener('click', (e) => {
    if (panel.getAttribute(ATTR_PANEL_MODE) !== 'gallery') return;
    const card = e.target.closest(`[${ATTR_GALLERY_CARD}]`);
    if (!card || !panel.contains(card)) return;
    e.preventDefault();
    if (onPickCallback) {
      onPickCallback({
        widget:   card.getAttribute('data-widget-name'),
        category: card.getAttribute('data-widget-category'),
        width:    parseInt(card.getAttribute('data-widget-default-w'), 10) || 1,
        height:   parseInt(card.getAttribute('data-widget-default-h'), 10) || 1,
        render:   card.getAttribute('data-widget-render'),
      });
    }
  });

  // The panel's `hidden` attribute is the canonical close signal
  // — flipped by configure.module.mjs's closeConfigure (which fires
  // for backdrop click, ✕ click, Cancel click) and our own
  // closeGallery. Clean up gallery state whenever the panel hides.
  const observer = new MutationObserver(muts => {
    for (const m of muts) {
      if (m.attributeName !== 'hidden') continue;
      if (panel.hasAttribute('hidden')) {
        panel.removeAttribute(ATTR_PANEL_MODE);
        onPickCallback = null;
        totalCardCount = 0;
        const body = panel.querySelector(`[${ATTR_PANEL_BODY}]`);
        if (body) {
          // Release the cloned card / category nodes so subsequent
          // opens don't accumulate stale DOM between renders.
          body.replaceChildren();
        }
      }
    }
  });
  observer.observe(panel, { attributes: true, attributeFilter: ['hidden'] });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
