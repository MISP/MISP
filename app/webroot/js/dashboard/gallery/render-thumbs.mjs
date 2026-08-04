// Render-kind glyphs for the widget gallery card thumbnails.
//
// Each render kind that widgets declare via `public $render` gets a
// simple shape glyph that visually evokes the widget's output:
// SimpleList → 3 horizontal rows; BarChart → 4 vertical bars;
// MultiLineChart → sloping polylines; WorldMap → globe; etc. Cards
// for widgets that don't declare a `$thumbnail` URL fall back to
// these glyphs, so the gallery never shows an empty gray slot.
//
// Single-color SVGs (currentColor) so the CSS layer picks the
// stroke / fill colour from the active theme. The viewBox is 16:9
// to match the `.misp-gallery-card-thumbnail` slot's aspect ratio.
// Width / height are unset so CSS controls the rendered size.
//
// ──────────────────────────────────────────────────────────────────
// ADDING A NEW RENDER KIND — required when you add a new value for
// `public $render` on any widget class under app/Lib/Dashboard/, or
// when you add a new template under app/View/Elements/dashboard/
// Widgets/. Without this, the gallery card for any widget that uses
// the new render kind falls through to `thumbGeneric` and ships a
// generic block — readable but visually undifferentiated from
// neighbours of other render kinds.
//
//   1. Add a `thumb<Name>()` builder function following the
//      existing pattern (use `svg(...)` + `shape(tag, attrs)` for
//      single-color geometry; opacity 0.35-0.7 for layered fills;
//      keep visible content roughly inside x=18..62, y=10..35 so
//      the glyph reads at small sizes).
//   2. Register the builder in the `REGISTRY` object at the bottom
//      of this file under the exact `$render` string the widget
//      declares — case-sensitive.
//   3. Glyph should evoke the widget's output SHAPE, not its data
//      domain. A bar chart is bars regardless of whether it's
//      counting events or orgs; the gallery groups by category
//      separately (it's an orthogonal concern).
//   4. No tests required; node --check is enough. Open the gallery
//      to verify visually — the new glyph should land for every
//      widget using the new render kind.
// ──────────────────────────────────────────────────────────────────

const VIEWBOX = '0 0 80 45';

const SVG_NS = 'http://www.w3.org/2000/svg';

function svg(children, opts = {}) {
  const root = document.createElementNS(SVG_NS, 'svg');
  root.setAttribute('viewBox', VIEWBOX);
  root.setAttribute('xmlns', SVG_NS);
  root.setAttribute('fill', opts.fill || 'none');
  root.setAttribute('stroke', opts.stroke || 'currentColor');
  root.setAttribute('stroke-width', opts.strokeWidth || '1.6');
  root.setAttribute('stroke-linecap', 'round');
  root.setAttribute('stroke-linejoin', 'round');
  root.setAttribute('aria-hidden', 'true');
  root.setAttribute('focusable', 'false');
  for (const c of children) root.appendChild(c);
  return root;
}

function shape(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    node.setAttribute(k, String(v));
  }
  return node;
}

// ---- per render kind glyph builders ----

function thumbSimpleList() {
  return svg([
    shape('rect', { x: 20, y: 12, width: 40, height: 4, rx: 2, fill: 'currentColor', stroke: 'none' }),
    shape('rect', { x: 20, y: 20.5, width: 40, height: 4, rx: 2, fill: 'currentColor', stroke: 'none', opacity: 0.7 }),
    shape('rect', { x: 20, y: 29, width: 40, height: 4, rx: 2, fill: 'currentColor', stroke: 'none', opacity: 0.45 }),
  ]);
}

function thumbBarChart() {
  return svg([
    shape('rect', { x: 22, y: 26, width: 7, height: 13, rx: 1.5, fill: 'currentColor', stroke: 'none', opacity: 0.5 }),
    shape('rect', { x: 32, y: 19, width: 7, height: 20, rx: 1.5, fill: 'currentColor', stroke: 'none', opacity: 0.7 }),
    shape('rect', { x: 42, y: 10, width: 7, height: 29, rx: 1.5, fill: 'currentColor', stroke: 'none' }),
    shape('rect', { x: 52, y: 22, width: 7, height: 17, rx: 1.5, fill: 'currentColor', stroke: 'none', opacity: 0.6 }),
  ]);
}

function thumbMultiLineChart() {
  return svg([
    shape('polyline', { points: '18,30 28,16 38,22 48,11 58,18 62,15' }),
    shape('polyline', { points: '18,24 28,30 38,18 48,28 58,33 62,29', opacity: 0.4 }),
  ]);
}

function thumbWorldMap() {
  return svg([
    shape('circle', { cx: 40, cy: 22.5, r: 13 }),
    shape('ellipse', { cx: 40, cy: 22.5, rx: 13, ry: 5 }),
    shape('line', { x1: 40, y1: 9.5, x2: 40, y2: 35.5 }),
  ]);
}

function thumbIndex() {
  return svg([
    shape('rect', { x: 22, y: 13, width: 36, height: 19, rx: 2 }),
    shape('line', { x1: 22, y1: 19, x2: 58, y2: 19 }),
    shape('line', { x1: 22, y1: 25, x2: 58, y2: 25 }),
    shape('line', { x1: 34, y1: 13, x2: 34, y2: 32 }),
    shape('line', { x1: 46, y1: 13, x2: 46, y2: 32 }),
  ]);
}

function thumbButton() {
  return svg([
    shape('rect', { x: 20, y: 16, width: 40, height: 13, rx: 6.5 }),
    shape('circle', { cx: 32, cy: 22.5, r: 1.5, fill: 'currentColor', stroke: 'none' }),
    shape('circle', { cx: 40, cy: 22.5, r: 1.5, fill: 'currentColor', stroke: 'none' }),
    shape('circle', { cx: 48, cy: 22.5, r: 1.5, fill: 'currentColor', stroke: 'none' }),
  ]);
}

function thumbOrgsPictures() {
  return svg([
    shape('circle', { cx: 30, cy: 22.5, r: 6 }),
    shape('circle', { cx: 40, cy: 22.5, r: 6, opacity: 0.7 }),
    shape('circle', { cx: 50, cy: 22.5, r: 6, opacity: 0.45 }),
  ]);
}

function thumbAttack() {
  // ATT&CK navigator vibe: 5x3 dot matrix.
  const dots = [];
  for (let row = 0; row < 3; row++) {
    for (let col = 0; col < 5; col++) {
      const cx = 28 + col * 6;
      const cy = 14 + row * 6;
      const opacity = 0.35 + ((col + row) % 3) * 0.25;
      dots.push(shape('circle', {
        cx, cy, r: 1.6,
        fill: 'currentColor', stroke: 'none', opacity,
      }));
    }
  }
  return svg(dots);
}

function thumbAchievements() {
  return svg([
    shape('circle', { cx: 40, cy: 22.5, r: 9 }),
    shape('polygon', {
      points: '40,17 41.3,20.8 45.4,20.8 42.1,23.2 43.3,27 40,24.7 36.7,27 37.9,23.2 34.6,20.8 38.7,20.8',
      fill: 'currentColor', stroke: 'none',
    }),
  ]);
}

function thumbMonitorLineChart() {
  // Single streaming line with a soft area fill — a live-monitor sparkline.
  return svg([
    shape('polyline', { points: '18,30 26,24 32,27 40,15 48,20 56,12 62,17' }),
    shape('path', {
      d: 'M18,30 26,24 32,27 40,15 48,20 56,12 62,17 62,36 18,36 Z',
      fill: 'currentColor', stroke: 'none', opacity: 0.18,
    }),
  ]);
}

function thumbPieChart() {
  // Pie circle + one filled ~120° wedge (12 o'clock clockwise to ~2 o'clock).
  return svg([
    shape('circle', { cx: 40, cy: 22.5, r: 12, opacity: 0.45 }),
    shape('path', { d: 'M40,22.5 L40,10.5 A12,12 0 0,1 50.4,28.5 Z', fill: 'currentColor', stroke: 'none' }),
  ]);
}

function thumbStatGrid() {
  // 2x2 grid of KPI cards, each with a short "value" bar inside —
  // evokes the metric-card layout regardless of the data domain.
  const card = (x, y) => [
    shape('rect', { x, y, width: 16, height: 13, rx: 2, opacity: 0.55 }),
    shape('rect', { x: x + 3, y: y + 4, width: 9, height: 4, rx: 1, fill: 'currentColor', stroke: 'none' }),
  ];
  return svg([
    ...card(24, 11),
    ...card(44, 11),
    ...card(24, 27),
    ...card(44, 27),
  ]);
}

function thumbNetworkGraph() {
  // Hub-and-spoke: a centre node with three edges out to ringed nodes.
  return svg([
    // edges first so the nodes sit on top
    shape('line', { x1: 40, y1: 22.5, x2: 24, y2: 13, opacity: 0.6 }),
    shape('line', { x1: 40, y1: 22.5, x2: 56, y2: 13, opacity: 0.6 }),
    shape('line', { x1: 40, y1: 22.5, x2: 40, y2: 37, opacity: 0.6 }),
    shape('circle', { cx: 40, cy: 22.5, r: 5, fill: 'currentColor', stroke: 'none' }),
    shape('circle', { cx: 24, cy: 13, r: 3.2, fill: 'currentColor', stroke: 'none', opacity: 0.65 }),
    shape('circle', { cx: 56, cy: 13, r: 3.2, fill: 'currentColor', stroke: 'none', opacity: 0.65 }),
    shape('circle', { cx: 40, cy: 37, r: 3.2, fill: 'currentColor', stroke: 'none', opacity: 0.65 }),
  ]);
}

function thumbUserList() {
  // A "people list": two rows, each an avatar circle on the left with a
  // long name bar + shorter meta bar to its right, plus a small badge dot.
  const row = (y) => [
    shape('circle', { cx: 24, cy: y + 3, r: 4 }),
    shape('rect', { x: 33, y: y, width: 22, height: 3.5, rx: 1.5, fill: 'currentColor', stroke: 'none' }),
    shape('rect', { x: 33, y: y + 5.5, width: 14, height: 3, rx: 1.5, fill: 'currentColor', stroke: 'none', opacity: 0.45 }),
    shape('circle', { cx: 60, cy: y + 3, r: 2, fill: 'currentColor', stroke: 'none', opacity: 0.7 }),
  ];
  return svg([
    ...row(12),
    ...row(27),
  ]);
}

function thumbQueueList() {
  // A "queue list": three stacked rows, each = small square glyph on the
  // left + a name bar + two short pill chips on the right (the workers
  // and jobs chips that QueueList renders per queue).
  const row = (y) => [
    shape('rect', { x: 16, y: y, width: 6, height: 6, rx: 1 }),
    shape('rect', { x: 26, y: y + 1, width: 16, height: 4, rx: 1.5, fill: 'currentColor', stroke: 'none', opacity: 0.55 }),
    shape('rect', { x: 46, y: y, width: 7, height: 6, rx: 2, fill: 'currentColor', stroke: 'none', opacity: 0.7 }),
    shape('rect', { x: 55, y: y, width: 7, height: 6, rx: 2, fill: 'currentColor', stroke: 'none', opacity: 0.35 }),
  ];
  return svg([
    ...row(9),
    ...row(20),
    ...row(31),
  ]);
}

function thumbHealthList() {
  // A "health-check list": stacked rows, each prefixed by a small severity
  // shape (triangle / circle alternating to evoke warn + fail), with a
  // name bar in the middle and a short pill chip on the right. Mirrors
  // the HealthList renderer's row shape.
  const triangleAt = (cx, cy) => shape('polygon', {
    points: `${cx},${cy - 3.2} ${cx + 3},${cy + 2.2} ${cx - 3},${cy + 2.2}`,
    fill: 'currentColor', stroke: 'none',
  });
  const circleAt = (cx, cy) => shape('circle', {
    cx, cy, r: 3, fill: 'currentColor', stroke: 'none',
  });
  const row = (y, mark) => [
    mark(20, y + 3),
    shape('rect', { x: 27, y, width: 22, height: 3.5, rx: 1.5, fill: 'currentColor', stroke: 'none', opacity: 0.55 }),
    shape('rect', { x: 27, y: y + 5, width: 12, height: 2.5, rx: 1, fill: 'currentColor', stroke: 'none', opacity: 0.3 }),
    shape('rect', { x: 52, y: y + 1, width: 10, height: 6, rx: 2, fill: 'currentColor', stroke: 'none', opacity: 0.7 }),
  ];
  return svg([
    ...row(9, triangleAt),
    ...row(20, circleAt),
    ...row(31, triangleAt),
  ]);
}

function thumbPewPewMap() {
  // A schematic world (soft continent blobs) with two arcs sweeping in
  // to a glowing destination — evokes the attacker→victim "pew pew"
  // arcs + the pulsing victim glow, independent of the data domain.
  const land = (cx, cy, rx, ry) => shape('ellipse', {
    cx, cy, rx, ry, fill: 'currentColor', stroke: 'none', opacity: 0.22,
  });
  return svg([
    land(18, 17, 7, 4),
    land(39, 13, 9, 4.5),
    land(59, 19, 7, 4),
    land(29, 33, 8, 4),
    // two arcs converging on the destination
    shape('path', { d: 'M18,32 Q30,8 44,25' }),
    shape('path', { d: 'M62,29 Q52,7 44,25' }),
    // origin dots
    shape('circle', { cx: 18, cy: 32, r: 2, fill: 'currentColor', stroke: 'none', opacity: 0.6 }),
    shape('circle', { cx: 62, cy: 29, r: 2, fill: 'currentColor', stroke: 'none', opacity: 0.6 }),
    // destination glow: filled core + ripple ring
    shape('circle', { cx: 44, cy: 25, r: 2.4, fill: 'currentColor', stroke: 'none' }),
    shape('circle', { cx: 44, cy: 25, r: 5, opacity: 0.5 }),
  ]);
}

function thumbTrending() {
  // Ranked-row list (analyst track, AD-W1): horizontal volume bars of
  // decreasing length (the rank / volume) with a small up-arrow evoking
  // the ▲/▼ momentum delta badge — reads as "ranked + rising", distinct
  // from SimpleList's equal rows and BarChart's vertical bars.
  return svg([
    shape('rect', { x: 20, y: 13, width: 30, height: 5, rx: 2, fill: 'currentColor', stroke: 'none' }),
    shape('rect', { x: 20, y: 22, width: 22, height: 5, rx: 2, fill: 'currentColor', stroke: 'none', opacity: 0.7 }),
    shape('rect', { x: 20, y: 31, width: 14, height: 5, rx: 2, fill: 'currentColor', stroke: 'none', opacity: 0.45 }),
    shape('polygon', { points: '58,11 62,17 54,17', fill: 'currentColor', stroke: 'none' }),
  ]);
}

function thumbEventCards() {
  // Stacked event cards (analyst track, AD-W6): a vertical stack of
  // rounded "cards", each with a small threat-dot on the left and a
  // short info line — evokes the flat reverse-chron card stream, distinct
  // from SimpleList's bare rows and StatGrid's 2x2 KPI grid.
  const card = (y, op) => [
    shape('rect', { x: 18, y, width: 44, height: 9, rx: 2, opacity: op }),
    shape('circle', { cx: 23, cy: y + 4.5, r: 1.7, fill: 'currentColor', stroke: 'none', opacity: op }),
    shape('rect', { x: 28, y: y + 3, width: 24, height: 3, rx: 1.5, fill: 'currentColor', stroke: 'none', opacity: op }),
  ];
  return svg([
    ...card(8, 1),
    ...card(19, 0.7),
    ...card(30, 0.45),
  ]);
}

function thumbFeedList() {
  // Reverse-chronological feed (analyst track, AD-17 / W10–W12): stacked
  // items, each a leading glyph dot + a title line with a shorter meta line
  // below — evokes the "icon · title · meta" feed, distinct from
  // EventCards' bordered cards, SimpleList's equal single rows and
  // StatGrid's 2×2 grid.
  const item = (y, op) => [
    shape('circle', { cx: 22, cy: y + 2, r: 2.2, fill: 'currentColor', stroke: 'none', opacity: op }),
    shape('rect', { x: 29, y, width: 31, height: 3.6, rx: 1.6, fill: 'currentColor', stroke: 'none', opacity: op }),
    shape('rect', { x: 29, y: y + 6, width: 19, height: 2.6, rx: 1.3, fill: 'currentColor', stroke: 'none', opacity: op * 0.55 }),
  ];
  return svg([
    ...item(11, 1),
    ...item(26, 0.7),
  ]);
}

function thumbGeneric() {
  return svg([
    shape('rect', { x: 22, y: 14, width: 36, height: 17, rx: 2 }),
    shape('line', { x1: 28, y1: 21, x2: 52, y2: 21, opacity: 0.5 }),
    shape('line', { x1: 28, y1: 25, x2: 44, y2: 25, opacity: 0.5 }),
  ]);
}

const REGISTRY = {
  SimpleList:     thumbSimpleList,
  BarChart:       thumbBarChart,
  MultiLineChart: thumbMultiLineChart,
  WorldMap:       thumbWorldMap,
  Index:          thumbIndex,
  Button:         thumbButton,
  OrgsPictures:   thumbOrgsPictures,
  Attack:         thumbAttack,
  Achievements:   thumbAchievements,
  PieChart:       thumbPieChart,
  MonitorLineChart: thumbMonitorLineChart,
  StatGrid:       thumbStatGrid,
  Trending:       thumbTrending,
  EventCards:     thumbEventCards,
  FeedList:       thumbFeedList,
  NetworkGraph:   thumbNetworkGraph,
  UserList:       thumbUserList,
  QueueList:      thumbQueueList,
  HealthList:     thumbHealthList,
  PewPewMap:      thumbPewPewMap,
};

/**
 * Return an SVG element for the given render kind, or a generic
 * block glyph when the kind is unknown / missing. Always returns
 * a fresh node — callers can mount it directly into the DOM.
 *
 * Render kinds match `public $render` on widget classes. The
 * in-tree set today is: SimpleList (12), MultiLineChart (9),
 * BarChart (8), WorldMap (3), Index (3), OrgsPictures (1),
 * Button (1), Attack (1), Achievements (1) — see
 * dashboard-progress.md and the `Widgets/<Kind>.ctp` renderer
 * dispatch for the authoritative list.
 */
export function getRenderThumb(renderKind) {
  const builder = REGISTRY[renderKind] || thumbGeneric;
  return builder();
}
