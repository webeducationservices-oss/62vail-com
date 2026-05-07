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
    if (window.parent === window) return; // not in an iframe
    var ref = '';
    try { ref = document.referrer ? new URL(document.referrer).hostname : ''; } catch (_) {}
    var inEditor = /(^|\.)myaieditor\.com$/.test(ref) || /(^|\.)myaiediter\.com$/.test(ref);
    if (!inEditor) return;
    var s = document.createElement('script');
    s.src = 'https://myaieditor.com/api/inline-edit/snippet';
    s.async = true;
    document.head.appendChild(s);
  } catch (_) { /* never block the page */ }
})();
