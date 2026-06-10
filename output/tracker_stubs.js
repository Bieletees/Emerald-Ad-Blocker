// Emerald Ad Blocker — tracker_stubs.js
// Injected by WKUserScript at document_start.
// Stubs the JavaScript APIs of common trackers.
(function () {
  'use strict';

  var _hostname = window.location.hostname;
  if (/\.(google|googleapis|gstatic)\.com$/.test(_hostname) ||
      /\.(spotify\.com|scdn\.co)$/.test(_hostname) ||
      /downdetector\.com$/.test(_hostname) ||
      /^(www\.|m\.|music\.|tv\.)?youtube\.com$/.test(_hostname) ||
      /^(www\.)?youtubekids\.com$/.test(_hostname) ||
      /(^|\.)statcounter\.com$/.test(_hostname) ||
      /(^|\.)kahoot\.(it|com)$/.test(_hostname) ||
      /(^|\.)microsoftonline\.com$/.test(_hostname) ||
      /(^|\.)microsoft\.com$/.test(_hostname) ||
      /^login\.live\.com$/.test(_hostname) ||
      /^account\.live\.com$/.test(_hostname) ||
      /(^|\.)bing\.com$/.test(_hostname) ||
      /(^|\.)msftauth\.net$/.test(_hostname) ||
      /(^|\.)msauth\.net$/.test(_hostname) ||
      /(^|\.)msecnd\.net$/.test(_hostname) ||
      /(^|\.)office\.com$/.test(_hostname) ||
      /(^|\.)office365\.com$/.test(_hostname) ||
      /(^|\.)outlook\.com$/.test(_hostname) ||
      /(^|\.)sharepoint\.com$/.test(_hostname) ||
      /(^|\.)windows\.net$/.test(_hostname) ||
      /(^|\.)azure\.com$/.test(_hostname) ||
      /(^|\.)azurewebsites\.net$/.test(_hostname)) {
    return;
  }

  var noop = function () {};
  var noopThis = function () { return this; };
  var noopObj = function () { return {}; };
  var noopStr = function () { return ''; };
  var noopFalse = function () { return false; };
  var noopTrue = function () { return true; };

  window['GoogleAnalyticsObject'] = 'ga';
  window.ga = window.ga || noop;
  window.ga.loaded = true;
  window.ga.create = noopObj;
  window.ga.getByName = noopObj;
  window.ga.getAll = function () { return []; };
  window.gtag = window.gtag || noop;
  window.dataLayer = window.dataLayer || [];
  if (typeof window.dataLayer.push !== 'function') { window.dataLayer.push = noop; }

  function _fbqStub() {}
  _fbqStub.callMethod = { apply: noop };
  _fbqStub.queue = []; _fbqStub.loaded = true; _fbqStub.version = '2.0';
  _fbqStub.push = noop; _fbqStub.track = noop; _fbqStub.trackCustom = noop;
  _fbqStub.init = noop; _fbqStub.pageView = noop; _fbqStub.consent = noop;
  if (!window.fbq) { window.fbq = _fbqStub; }
  if (!window._fbq) { window._fbq = _fbqStub; }

  if (!window.mixpanel) { window.mixpanel = { init: noop, track: noop, identify: noop, reset: noop, people: { set: noop } }; }
  if (!window.amplitude) { window.amplitude = { init: noop, logEvent: noop, getInstance: function() { return window.amplitude; } }; }
  window.hj = window.hj || noop;
  if (!window.heap) { window.heap = { load: noop, track: noop, identify: noop }; }
  if (!window.FS) { window.FS = { identify: noop, event: noop, shutdown: noop }; }
  if (!window.analytics) { window.analytics = { identify: noop, track: noop, page: noop, load: noop }; }
  window.Intercom = window.Intercom || noop;
  if (!window.drift) { window.drift = { load: noop, identify: noop, track: noop }; }
  if (!window.ttq) { window.ttq = { load: noop, page: noop, track: noop, identify: noop }; }
  window.pintrk = window.pintrk || noop;
  window.twq = window.twq || noop;
  window.snaptr = window.snaptr || noop;
  window.lintrk = window.lintrk || noop;
  window.clarity = window.clarity || noop;

})();