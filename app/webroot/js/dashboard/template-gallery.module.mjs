/**
 * Template gallery module (PRD §5.4, Phase 4 task 1).
 *
 * The /dashboards/listTemplates page server-renders every card up
 * front (server has the data; cards are static). The only client-
 * side concern is the search filter: typing in the search box hides
 * cards whose `data-template-search-text` payload doesn't contain
 * the typed terms. Sections whose cards are all hidden collapse so
 * the user doesn't stare at an empty "Shared with me" heading.
 *
 * Stable hook contract (mirrors the widget gallery's data-* convention):
 *   data-misp-template-gallery-root     — gallery shell root
 *   data-misp-template-gallery-search   — search input
 *   data-misp-template-gallery-counter  — "N of M" live count
 *   data-misp-template-gallery-body     — body wrapping the sections
 *   data-misp-template-gallery-empty    — no-match message
 *   data-misp-template-gallery-section  — section root (mine/featured/shared)
 *   data-misp-template-card             — single card
 *   data-template-search-text           — pre-computed lowercase blob
 *                                          (name + description + uuid +
 *                                          owner email) used by the
 *                                          search comparator
 *
 * The search-text payload is computed server-side and stamped into
 * the data attribute so this module doesn't have to walk per-card
 * DOM nodes on every keystroke. Empty query reveals all cards.
 */

const ATTR_ROOT     = 'data-misp-template-gallery-root';
const ATTR_SEARCH   = 'data-misp-template-gallery-search';
const ATTR_COUNTER  = 'data-misp-template-gallery-counter';
const ATTR_SECTION  = 'data-misp-template-gallery-section';
const ATTR_EMPTY    = 'data-misp-template-gallery-empty';
const ATTR_CARD     = 'data-misp-template-card';
const ATTR_SEARCH_TEXT = 'data-template-search-text';

function init() {
  const root = document.querySelector(`[${ATTR_ROOT}]`);
  if (!root) return;
  const input    = root.querySelector(`[${ATTR_SEARCH}]`);
  const counter  = root.querySelector(`[${ATTR_COUNTER}]`);
  const emptyMsg = root.querySelector(`[${ATTR_EMPTY}]`);
  const cards    = Array.from(root.querySelectorAll(`[${ATTR_CARD}]`));
  const sections = Array.from(root.querySelectorAll(`[${ATTR_SECTION}]`));
  const total = cards.length;

  function updateCounter(visible) {
    if (!counter) return;
    counter.textContent = visible === total
      ? `${total} template${total === 1 ? '' : 's'}`
      : `${visible} of ${total}`;
  }

  function applyFilter(query) {
    const q = (query || '').trim().toLowerCase();
    let visible = 0;
    for (const card of cards) {
      const haystack = card.getAttribute(ATTR_SEARCH_TEXT) || '';
      const match = !q || haystack.includes(q);
      card.hidden = !match;
      if (match) visible += 1;
    }
    // Collapse empty sections so headings don't sit alone.
    for (const section of sections) {
      const anyVisible = Array.from(
        section.querySelectorAll(`[${ATTR_CARD}]`)
      ).some(c => !c.hidden);
      section.hidden = !anyVisible;
    }
    updateCounter(visible);
    if (emptyMsg) emptyMsg.hidden = (visible !== 0 || total === 0);
  }

  // Initial counter (no filter yet).
  updateCounter(total);

  if (input) {
    input.addEventListener('input', () => applyFilter(input.value));
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
