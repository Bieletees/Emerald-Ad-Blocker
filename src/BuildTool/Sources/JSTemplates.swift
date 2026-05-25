/// JS template files for Emerald Ad Blocker output.
/// These are written to output/ by the build tool.

import Foundation

// MARK: - websocket_block.js (static)

let websocketBlockJS = #"""
// Emerald Ad Blocker — websocket_block.js (v3.1)
// Injected by WKUserScript at document_start.
// Blocks WebSocket connections to known trackers and prevents WebRTC IP leaks.
(function () {
  'use strict';

  var _wsHost = window.location.hostname;
  if (/\.(google|googleapis|gstatic)\.com$/.test(_wsHost) ||
      /downdetector\.com$/.test(_wsHost) ||
      /^(www\.|m\.|music\.|tv\.)?youtube\.com$/.test(_wsHost) ||
      /^(www\.)?youtubekids\.com$/.test(_wsHost) ||
      /(^|\.)statcounter\.com$/.test(_wsHost) ||
      /(^|\.)kahoot\.(it|com)$/.test(_wsHost)) {
    return;
  }

  function nativize(wrapper, original) {
    var nativeStr = 'function ' + (original.name || '') + '() { [native code] }';
    wrapper.toString = function () { return nativeStr; };
    return wrapper;
  }

  var _WS = window.WebSocket;
  var BLOCKED_WS = [
    /google-analytics/i, /doubleclick/i, /googlesyndication/i,
    /facebook\.net/i, /fbcdn\.net.*beacon/i,
    /hotjar\.com/i, /fullstory\.com/i, /segment\.(com|io)/i,
    /mixpanel\.com/i, /amplitude\.com/i,
    /clarity\.ms/i, /mouseflow\.com/i,
    /taboola\.com/i, /outbrain\.com/i,
    /criteo\.(com|net)/i, /pubmatic\.com/i,
    /adnxs\.com/i, /rubiconproject\.com/i,
  ];

  var _wsWrapper = function (url, protocols) {
    var urlStr = String(url);
    for (var i = 0; i < BLOCKED_WS.length; i++) {
      if (BLOCKED_WS[i].test(urlStr)) {
        return {
          readyState: 3, CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3,
          send: function () {}, close: function () {},
          addEventListener: function () {}, removeEventListener: function () {},
          onopen: null, onclose: null, onmessage: null, onerror: null,
          binaryType: 'blob', bufferedAmount: 0, extensions: '', protocol: '',
          url: urlStr,
        };
      }
    }
    if (protocols !== undefined) return new _WS(url, protocols);
    return new _WS(url);
  };
  window.WebSocket = nativize(_wsWrapper, _WS);
  window.WebSocket.prototype = _WS.prototype;
  window.WebSocket.CONNECTING = 0;
  window.WebSocket.OPEN = 1;
  window.WebSocket.CLOSING = 2;
  window.WebSocket.CLOSED = 3;

  var _RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
  if (_RTC) {
    var _rtcWrapper = function (config, constraints) {
      if (config && config.iceServers) { config.iceServers = []; }
      return new _RTC(config, constraints);
    };
    window.RTCPeerConnection = nativize(_rtcWrapper, _RTC);
    window.RTCPeerConnection.prototype = _RTC.prototype;
    if (window.webkitRTCPeerConnection) {
      window.webkitRTCPeerConnection = window.RTCPeerConnection;
    }
  }

  var _beacon = navigator.sendBeacon;
  var BLOCKED_BEACON = [
    /google-analytics\.com/i, /doubleclick\.net/i,
    /facebook\.net\/tr/i, /connect\.facebook\.net/i,
    /hotjar\.com/i, /fullstory\.com/i,
    /segment\.(com|io)\/v1/i, /mixpanel\.com/i,
    /amplitude\.com/i, /clarity\.ms/i,
    /mouseflow\.com/i, /taboola\.com/i,
    /criteo\.(com|net)/i, /pubmatic\.com/i,
  ];

  if (_beacon) {
    navigator.sendBeacon = nativize(function (url) {
      var urlStr = String(url);
      for (var i = 0; i < BLOCKED_BEACON.length; i++) {
        if (BLOCKED_BEACON[i].test(urlStr)) return true;
      }
      return _beacon.apply(navigator, arguments);
    }, _beacon);
  }

})();
"""#

// MARK: - tracker_stubs.js (static)

let trackerStubsJS = #"""
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
      /(^|\.)kahoot\.(it|com)$/.test(_hostname)) {
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
"""#

// MARK: - cosmetic.js template

func buildCosmeticJS() -> String {
    return #"""
// Emerald Ad Blocker — cosmetic.js (v4.0)
// Injected by WKUserScript at document_start.
(function () {
  'use strict';

  var _cosHost = window.location.hostname;
  var _skipCSSHiding = /\.(spotify\.com|scdn\.co)$/.test(_cosHost) ||
      /\.(google|googleapis|gstatic)\.com$/.test(_cosHost) ||
      /^(www\.|m\.|music\.|tv\.)?youtube\.com$/.test(_cosHost) ||
      /^(www\.)?youtubekids\.com$/.test(_cosHost) ||
      /(^|\.)statcounter\.com$/.test(_cosHost) ||
      /(^|\.)kahoot\.(it|com)$/.test(_cosHost);

  // ── 1. Anti-adblock stubs ────────────────────────────────────────────────
  try { Object.defineProperty(window, 'canRunAds', { get: function () { return true; }, configurable: true }); } catch (_) {}
  try { Object.defineProperty(window, 'canShowAds', { get: function () { return true; }, configurable: true }); } catch (_) {}
  try { Object.defineProperty(window, 'ads_loaded', { get: function () { return true; }, configurable: true }); } catch (_) {}
  try { Object.defineProperty(window, 'adBlockEnabled', { get: function () { return false; }, configurable: true }); } catch (_) {}
  try { Object.defineProperty(window, 'adBlockDetected', { get: function () { return false; }, configurable: true }); } catch (_) {}
  try { Object.defineProperty(window, 'adblock', { get: function () { return false; }, configurable: true }); } catch (_) {}
  try { Object.defineProperty(window, 'google_ad_status', { get: function () { return 1; }, configurable: true }); } catch (_) {}

  // ── 1b. Bait element protection ──────────────────────────────────────────
  var _baitClasses = /^(ad|ads|adsbox|ad-banner|ad-placeholder|adbanner|advert|advertisement|banner_ad|sponsor)$/i;
  var _baitIds = /^(ad|ads|adsbox|ad-banner|banner-ad|ad-placeholder)$/i;

  try {
    var _origGetComputedStyle = window.getComputedStyle;
    window.getComputedStyle = function (el, pseudo) {
      var result = _origGetComputedStyle.call(this, el, pseudo);
      if (el && el.nodeType === 1) {
        var cls = el.className || '';
        var id = el.id || '';
        if ((_baitClasses.test(cls) || _baitIds.test(id)) &&
            result.getPropertyValue('display') === 'none') {
          return new Proxy(result, {
            get: function (target, prop) {
              if (prop === 'display') return 'block';
              if (prop === 'visibility') return 'visible';
              if (prop === 'opacity') return '1';
              if (prop === 'height') return '1px';
              if (prop === 'getPropertyValue') return function (p) {
                if (p === 'display') return 'block';
                if (p === 'visibility') return 'visible';
                if (p === 'opacity') return '1';
                if (p === 'height') return '1px';
                return target.getPropertyValue(p);
              };
              var val = target[prop];
              return typeof val === 'function' ? val.bind(target) : val;
            }
          });
        }
      }
      return result;
    };

    var _origOffsetHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
    var _origOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
    if (_origOffsetHeight && _origOffsetHeight.get) {
      Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
        get: function () {
          var cls = this.className || ''; var id = this.id || '';
          if (_baitClasses.test(cls) || _baitIds.test(id)) {
            var h = _origOffsetHeight.get.call(this); return h === 0 ? 1 : h;
          }
          return _origOffsetHeight.get.call(this);
        }, configurable: true
      });
    }
    if (_origOffsetWidth && _origOffsetWidth.get) {
      Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
        get: function () {
          var cls = this.className || ''; var id = this.id || '';
          if (_baitClasses.test(cls) || _baitIds.test(id)) {
            var w = _origOffsetWidth.get.call(this); return w === 0 ? 1 : w;
          }
          return _origOffsetWidth.get.call(this);
        }, configurable: true
      });
    }
  } catch (_) {}

  // ── 1c. adsbygoogle + googletag stubs ────────────────────────────────────
  if (!window.adsbygoogle || !Array.isArray(window.adsbygoogle)) {
    try {
      var _abl = []; _abl.loaded = true; _abl.push = function () {};
      Object.defineProperty(window, 'adsbygoogle', { get: function () { return _abl; }, configurable: true });
    } catch (_) {}
  }

  var _isGoogleOrigin = /\.(google|googleapis|gstatic)\.com$/.test(_cosHost) ||
      /^(www\.|m\.|music\.|tv\.)?youtube\.com$/.test(_cosHost) ||
      /^(www\.)?youtubekids\.com$/.test(_cosHost);

  if (!_isGoogleOrigin) {
    try {
      var _gtSlot = { addService: function(){return _gtSlot;}, defineSizeMapping: function(){return _gtSlot;}, setTargeting: function(){return _gtSlot;}, setCollapseEmptyDiv: function(){return _gtSlot;}, getSlotElementId: function(){return '';}, getAdUnitPath: function(){return '';} };
      var _gtPubads = { addEventListener: function(){}, removeEventListener: function(){}, setTargeting: function(){return _gtPubads;}, collapseEmptyDivs: function(){}, enableSingleRequest: function(){}, enableLazyLoad: function(){}, set: function(){return _gtPubads;}, get: function(){return null;}, refresh: function(){}, display: function(){}, disableInitialLoad: function(){}, clearTargeting: function(){return _gtPubads;}, getTargeting: function(){return [];}, getTargetingKeys: function(){return [];}, updateCorrelator: function(){}, setPrivacySettings: function(){return _gtPubads;}, getSlots: function(){return [];} };
      var _googletag = { cmd: { push: function(fn){try{fn();}catch(_){}} }, pubads: function(){return _gtPubads;}, companionAds: function(){return {};}, content: function(){return {};}, sizeMapping: function(){return {addSize:function(){return this;},build:function(){return [];}};}, defineSlot: function(){return _gtSlot;}, defineOutOfPageSlot: function(){return _gtSlot;}, display: function(){}, enableServices: function(){}, destroySlots: function(){}, getVersion: function(){return '';}, apiReady: true };
      if (!window.googletag || !window.googletag.pubads) { window.googletag = _googletag; }
      else { window.googletag.cmd = window.googletag.cmd || _googletag.cmd; }
    } catch (_) {}
  }

  // ── 2. CSS hiding ─────────────────────────────────────────────────────────
  if (!_skipCSSHiding) {
    var SELECTORS = [
      '[id^="google_ads_"]','[id^="div-gpt-ad"]','[id^="dfp-ad-"]',
      '.adsbygoogle','ins.adsbygoogle','.gpt-ad','.dfp-ad',
      '[data-ad-unit]','[data-adunit]','[data-google-query-id]',
      '[id*="taboola"]','[class*="taboola"]',
      '[id*="outbrain"]','[class*="outbrain"]',
      '[id*="revcontent"]','[class*="revcontent"]',
      '[class*="sponsored-content"]','[class*="sponsored_content"]','[class*="native-ad"]',
      '[data-ad-placeholder]','[data-advertisement]',
      '.ad-banner','.ad-container','.ad-wrapper','.ad-slot',
      '.advertisement','.advertising','.advertise',
      '.duet--ad','[data-concert-ads-name]','.c-leaderboard',
      '.l-ad','.ad__container','.chorus-ad',
      'iframe[src*="doubleclick.net"]','iframe[src*="googlesyndication.com"]',
      'iframe[src*="adnxs.com"]','iframe[src*="pubmatic.com"]',
      'shreddit-ad-post','.promotedlink',
      '[data-testid="post-container"][data-promoted="true"]',
    ];

    var _allSelectors = SELECTORS.join(',');
    function injectCSS() {
      var style = document.createElement('style');
      style.id = '__emerald_cosmetic_0__';
      style.textContent = SELECTORS.join(',\n') + ' { display: none !important; height: 0 !important; overflow: hidden !important; margin: 0 !important; padding: 0 !important; }';
      (document.head || document.documentElement).appendChild(style);
    }
    if (document.head || document.documentElement) { injectCSS(); }
    else { document.addEventListener('DOMContentLoaded', injectCSS, { once: true }); }

    var _hidden = new WeakSet();
    var _pending = false;
    function scanAndHide() {
      _pending = false;
      try {
        var matches = document.querySelectorAll(_allSelectors);
        for (var i = 0; i < matches.length; i++) {
          if (!_hidden.has(matches[i])) {
            matches[i].style.setProperty('display', 'none', 'important');
            _hidden.add(matches[i]);
          }
        }
      } catch (_) {}
    }
    new MutationObserver(function () {
      if (!_pending) { _pending = true; requestAnimationFrame(scanAndHide); }
    }).observe(document.documentElement, { childList: true, subtree: true });
  }

  // ── 2b. YouTube sponsored content removal ─────────────────────────────────
  // ytadblock.js handles video ads at the data level. This catches sponsored
  // recommendations that load dynamically via SPA navigation.
  // Uses JS-only removal (no <style> injection) to avoid detection.
  if (/^(www\.|m\.|music\.)?youtube\.com$/.test(_cosHost)) {
    var _ytPending = false;
    var _ytSelectors = 'ytd-ad-slot-renderer,ytd-promoted-sparkles-web-renderer,ytd-display-ad-renderer,ytd-promoted-video-renderer,ytd-compact-promoted-video-renderer,ytd-banner-promo-renderer,#masthead-ad';
    new MutationObserver(function () {
      if (!_ytPending) {
        _ytPending = true;
        requestAnimationFrame(function () {
          _ytPending = false;
          try {
            var els = document.querySelectorAll(_ytSelectors);
            for (var i = 0; i < els.length; i++) {
              els[i].remove();
            }
          } catch (_) {}
        });
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
  }

})();
"""#
}

// MARK: - scriptlets.js template

func buildScriptletsJS(siteConfigs: [String: [[String]]]) -> String {
    let siteConfigJSON: String
    if let data = try? JSONSerialization.data(withJSONObject: siteConfigs, options: []),
       let str = String(data: data, encoding: .utf8) {
        siteConfigJSON = str
    } else {
        siteConfigJSON = "{}"
    }

    return #"""
// Emerald Ad Blocker — scriptlets.js (v4.0)
// Injected by WKUserScript at document_start.
(function () {
  'use strict';

  if (window.self !== window.top) {
    try { window.top.location.href; } catch (e) { return; }
  }

  var _scriptletHost = window.location.hostname;
  if (/\.(google|googleapis|gstatic)\.com$/.test(_scriptletHost) ||
      /downdetector\.com$/.test(_scriptletHost) ||
      /^(www\.|m\.|music\.|tv\.)?youtube\.com$/.test(_scriptletHost) ||
      /^(www\.)?youtubekids\.com$/.test(_scriptletHost) ||
      /(^|\.)statcounter\.com$/.test(_scriptletHost) ||
      /(^|\.)kahoot\.(it|com)$/.test(_scriptletHost)) {
    return;
  }

  var _noop = function () {};

  function nativize(wrapper, original) {
    var nativeStr = 'function ' + (original.name || '') + '() { [native code] }';
    wrapper.toString = function () { return nativeStr; };
    if (original.prototype) wrapper.prototype = original.prototype;
    return wrapper;
  }

  function setConstant(chain, valueStr) {
    var value = valueStr === 'true' ? true : valueStr === 'false' ? false :
      valueStr === 'noopFunc' || valueStr === 'noop' ? _noop :
      valueStr === 'trueFunc' ? function(){return true;} :
      valueStr === 'falseFunc' ? function(){return false;} : valueStr;
    var parts = chain.split('.'); var last = parts.pop();
    var obj = window;
    for (var i = 0; i < parts.length; i++) {
      if (obj[parts[i]] === undefined) obj[parts[i]] = {};
      obj = obj[parts[i]];
    }
    try { Object.defineProperty(obj, last, { get: function(){return value;}, set: _noop, enumerable: true, configurable: false }); }
    catch(_) { try { obj[last] = value; } catch(_2){} }
  }

  function noFetchIf(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _fetch = window.fetch;
    if (typeof _fetch !== 'function') return;
    window.fetch = nativize(function (input) {
      var url = typeof input === 'string' ? input : (input && input.url) || '';
      if (!re || re.test(url)) { return Promise.resolve(new Response(null, { status: 200, statusText: 'OK' })); }
      return _fetch.apply(this, arguments);
    }, _fetch);
  }

  function noXhrIf(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = nativize(function (method, url) {
      if (!re || re.test(url)) { Object.defineProperty(this, '_blocked', { value: true, configurable: true }); }
      return _open.apply(this, arguments);
    }, _open);
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = nativize(function () {
      if (this._blocked) { return; }
      return _send.apply(this, arguments);
    }, _send);
  }

  function preventSetTimeout(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _st = window.setTimeout;
    window.setTimeout = nativize(function (fn, d) {
      var src = typeof fn === 'function' ? fn.toString() : String(fn);
      if (re && re.test(src)) return 0;
      return _st.apply(this, arguments);
    }, _st);
  }

  function preventSetInterval(pattern) {
    var re = pattern ? new RegExp(pattern) : null;
    var _si = window.setInterval;
    window.setInterval = nativize(function (fn, d) {
      var src = typeof fn === 'function' ? fn.toString() : String(fn);
      if (re && re.test(src)) return 0;
      return _si.apply(this, arguments);
    }, _si);
  }

  var DISPATCH = {
    'set-constant': function(a){ setConstant(a[0], a[1]); },
    'no-fetch-if': function(a){ noFetchIf(a[0]); },
    'no-xhr-if': function(a){ noXhrIf(a[0]); },
    'prevent-setTimeout': function(a){ preventSetTimeout(a[0]); },
    'no-setTimeout-if': function(a){ preventSetTimeout(a[0]); },
    'prevent-setInterval': function(a){ preventSetInterval(a[0]); },
    'no-setInterval-if': function(a){ preventSetInterval(a[0]); },
  };

  function run(name, args) {
    var fn = DISPATCH[name];
    if (fn) { try { fn(args || []); } catch (_) {} }
  }

  // ── Anti-adblock stubs ──────────────────────────────────────────────────
  setConstant('adsbygoogle.loaded', 'true');
  setConstant('adsbygoogle.push', 'noopFunc');
  setConstant('canRunAds', 'true');
  setConstant('blockAdBlock', 'noopFunc');
  setConstant('adsBlocked', 'false');
  setConstant('ads_not_blocked', 'true');
  setConstant('fuckAdBlock', 'noopFunc');
  setConstant('sniffAdBlock', 'noopFunc');
  setConstant('detectAdBlock', 'noopFunc');
  setConstant('check_adblock', 'noopFunc');
  setConstant('isAdBlockActive', 'false');
  setConstant('Admiral', 'noopFunc');

  preventSetTimeout('blockadblock|BlockAdBlock|fuckAdBlock|FuckAdBlock');
  preventSetInterval('blockadblock|BlockAdBlock|fuckAdBlock|FuckAdBlock');

  // ── Per-domain scriptlet configs ──────────────────────────────────────────
  var SITE_CONFIGS = \#(siteConfigJSON);
  var _host = _scriptletHost.replace(/^www\./, '');
  var _domainParts = _host.split('.');
  for (var _d = 0; _d < _domainParts.length - 1; _d++) {
    var _domainKey = _domainParts.slice(_d).join('.');
    var _siteRules = SITE_CONFIGS[_domainKey];
    if (_siteRules) {
      for (var _s = 0; _s < _siteRules.length; _s++) {
        run(_siteRules[_s][0], _siteRules[_s].slice(1));
      }
      break;
    }
  }

})();
"""#
}
