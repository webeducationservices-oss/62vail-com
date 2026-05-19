/**
 * myaieditor inline-edit loader
 *
 * Detects "am I being framed by myaieditor?" If yes, dynamically loads
 * the editor JS from myaieditor.com. If no (a real visitor), exits
 * immediately and adds zero overhead — production stays as fast as ever.
 *
 * To remove inline-edit support: just delete this file and the
 * <script> tag that loads it from <head>. No other dependencies.
 */
(function () {
  'use strict';
  try {
    if (window.parent === window) return; // not in an iframe — never the editor

    // The referrer only names myaieditor on the FIRST page load in the
    // preview iframe. As soon as the user clicks a link to navigate
    // within the iframe, document.referrer becomes the previous page on
    // THIS site — so the referrer check would wrongly fail and editing
    // would silently switch off. Fix: on first detection, set a
    // sessionStorage flag (it persists across same-origin navigations
    // inside this iframe) and trust it on every later page.
    var KEY = '__maeInEditor';
    var ref = '';
    try { ref = document.referrer ? new URL(document.referrer).hostname : ''; } catch (_) {}
    var refIsEditor = /(^|\.)myaieditor\.com$/.test(ref) || /(^|\.)myaiediter\.com$/.test(ref);

    var inEditor = refIsEditor;
    try {
      if (refIsEditor) {
        sessionStorage.setItem(KEY, '1');
      } else if (sessionStorage.getItem(KEY) === '1') {
        inEditor = true;
      }
    } catch (_) {
      // sessionStorage blocked (rare privacy modes) — fall back to the
      // referrer check alone. Editing still works on the first page.
    }

    if (!inEditor) return;

    var s = document.createElement('script');
    s.src = 'https://myaieditor.com/api/inline-edit/snippet';
    s.async = true;
    document.head.appendChild(s);
  } catch (_) { /* never block the page */ }
})();
