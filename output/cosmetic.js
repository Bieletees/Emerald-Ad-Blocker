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