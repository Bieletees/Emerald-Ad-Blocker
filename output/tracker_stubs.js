// Emerald Ad Blocker — tracker_stubs.js
// Injected by WKUserScript at document_start.
//
// Stubs the JavaScript APIs of common trackers so that any tracker script
// which loads despite network blocking fails silently rather than throwing
// or retrying.  All functions are no-ops; none of the data they would have
// sent ever leaves the device.
//
// Covered trackers
// ────────────────
// Google Analytics (Universal / GA4), Facebook Pixel, Mixpanel, Amplitude,
// Hotjar, Heap, FullStory, Segment, Intercom, Drift, TikTok Pixel,
// Pinterest Tag, Criteo, Twitter/X Pixel, Snapchat Pixel, LinkedIn Insight,
// Microsoft Clarity, Mouseflow, Lucky Orange, VWO, Optimizely.

(function () {
  'use strict';

  var noop = function () {};
  var noopThis = function () { return this; };
  var noopObj = function () { return {}; };
  var noopStr = function () { return ''; };
  var noopFalse = function () { return false; };
  var noopTrue = function () { return true; };

  // ── Google Analytics (Universal Analytics + GA4) ───────────────────────

  window['GoogleAnalyticsObject'] = 'ga';
  window.ga = window.ga || noop;
  window.ga.loaded = true;
  window.ga.create = noopObj;
  window.ga.getByName = noopObj;
  window.ga.getAll = function () { return []; };

  window.gtag = window.gtag || noop;

  window.dataLayer = window.dataLayer || [];
  if (typeof window.dataLayer.push !== 'function') {
    window.dataLayer.push = noop;
  }

  // ── Facebook Pixel ─────────────────────────────────────────────────────

  function _fbqStub() {}
  _fbqStub.callMethod = { apply: noop };
  _fbqStub.queue = [];
  _fbqStub.loaded = true;
  _fbqStub.version = '2.0';
  _fbqStub.push = noop;
  _fbqStub.track = noop;
  _fbqStub.trackCustom = noop;
  _fbqStub.init = noop;
  _fbqStub.pageView = noop;
  _fbqStub.consent = noop;
  if (!window.fbq) { window.fbq = _fbqStub; }
  if (!window._fbq) { window._fbq = _fbqStub; }

  // ── Mixpanel ───────────────────────────────────────────────────────────

  var _mixpanel = {
    init: noop,
    track: noop,
    track_links: noop,
    track_forms: noop,
    track_pageview: noop,
    identify: noop,
    alias: noop,
    name_tag: noop,
    set_config: noop,
    register: noop,
    register_once: noop,
    unregister: noop,
    opt_in_tracking: noop,
    opt_out_tracking: noop,
    has_opted_in_tracking: noopFalse,
    has_opted_out_tracking: noopTrue,
    get_distinct_id: noopStr,
    get_property: noop,
    reset: noop,
    push: noop,
    people: {
      set: noop, set_once: noop, unset: noop, increment: noop,
      append: noop, union: noop, track_charge: noop, clear_charges: noop,
      delete_user: noop,
    },
    get_group: noopObj,
    set_group: noop,
    add_group: noop,
    remove_group: noop,
    track_with_groups: noop,
  };
  if (!window.mixpanel) { window.mixpanel = _mixpanel; }

  // ── Amplitude ──────────────────────────────────────────────────────────

  function _AmplitudeIdentify() {}
  _AmplitudeIdentify.prototype.set = noopThis;
  _AmplitudeIdentify.prototype.setOnce = noopThis;
  _AmplitudeIdentify.prototype.unset = noopThis;
  _AmplitudeIdentify.prototype.add = noopThis;
  _AmplitudeIdentify.prototype.append = noopThis;
  _AmplitudeIdentify.prototype.prepend = noopThis;

  var _amplitude = {
    init: noop,
    logEvent: noop,
    logEventWithTimestamp: noop,
    logEventWithGroups: noop,
    setUserId: noop,
    setUserProperties: noop,
    clearUserProperties: noop,
    setGroup: noop,
    setVersionName: noop,
    setOptOut: noop,
    setSessionId: noop,
    identify: noop,
    groupIdentify: noop,
    getInstance: function () { return _amplitude; },
    Identify: _AmplitudeIdentify,
    Revenue: function () { return { setProductId: noopThis, setQuantity: noopThis, setPrice: noopThis }; },
  };
  if (!window.amplitude) { window.amplitude = _amplitude; }

  // ── Hotjar ─────────────────────────────────────────────────────────────

  window.hj = window.hj || noop;
  window._hjSettings = window._hjSettings || {};
  window.hjBootstrap = window.hjBootstrap || noop;
  window.hjBootstrapCalled = true;

  // ── Heap ───────────────────────────────────────────────────────────────

  var _heap = {
    load: noop,
    track: noop,
    identify: noop,
    resetIdentity: noop,
    addUserProperties: noop,
    addEventProperties: noop,
    removeEventProperty: noop,
    clearEventProperties: noop,
    appid: '',
    userId: null,
    config: {},
  };
  if (!window.heap) { window.heap = _heap; }

  // ── FullStory ──────────────────────────────────────────────────────────

  var _FS = {
    identify: noop,
    setUserVars: noop,
    setVars: noop,
    event: noop,
    consent: noop,
    shutdown: noop,
    restart: noop,
    log: noop,
    anonymize: noop,
    getCurrentSessionURL: noopStr,
    getCurrentSession: noopStr,
  };
  if (!window.FS) { window.FS = _FS; }
  window._fs_loaded = true;
  window._fs_is_outer_window = true;

  // ── Segment / Analytics.js ─────────────────────────────────────────────

  var _analytics = {
    identify: noop,
    track: noop,
    page: noop,
    group: noop,
    alias: noop,
    ready: function (fn) { if (typeof fn === 'function') { try { fn(); } catch (_) {} } },
    on: noop,
    off: noop,
    once: noop,
    reset: noop,
    load: noop,
    push: noop,
    user: function () { return { id: noopStr, traits: function () { return {}; } }; },
  };
  if (!window.analytics || typeof window.analytics.track !== 'function') {
    window.analytics = _analytics;
  }

  // ── Intercom ───────────────────────────────────────────────────────────

  window.Intercom = window.Intercom || noop;
  window.intercomSettings = window.intercomSettings || {};

  // ── Drift ──────────────────────────────────────────────────────────────

  var _drift = {
    load: noop, identify: noop, track: noop, reset: noop,
    on: noop, off: noop, once: noop, page: noop, ping: noop,
    api: { widget: { hide: noop, show: noop, toggle: noop } },
  };
  if (!window.drift) { window.drift = _drift; }
  if (!window.driftt) { window.driftt = _drift; }

  // ── TikTok Pixel ───────────────────────────────────────────────────────

  var _ttq = {
    load: noop, page: noop, track: noop, identify: noop,
    instance: function () { return _ttq; },
    debug: noop, on: noop, off: noop, once: noop, emit: noop,
    push: noop,
  };
  if (!window.ttq) { window.ttq = _ttq; }

  // ── Pinterest Tag ──────────────────────────────────────────────────────

  window.pintrk = window.pintrk || noop;

  // ── Criteo ─────────────────────────────────────────────────────────────

  window.Criteo = window.Criteo || { events: { push: noop } };
  window.criteo_q = window.criteo_q || [];
  if (typeof window.criteo_q.push !== 'function') {
    window.criteo_q.push = noop;
  }

  // ── Twitter / X Pixel ─────────────────────────────────────────────────

  window.twq = window.twq || noop;

  // ── Snapchat Pixel ─────────────────────────────────────────────────────

  window.snaptr = window.snaptr || noop;

  // ── LinkedIn Insight Tag ───────────────────────────────────────────────

  window._linkedin_partner_id = window._linkedin_partner_id || '';
  window._linkedin_data_partner_ids = window._linkedin_data_partner_ids || [];
  window.lintrk = window.lintrk || noop;

  // ── Microsoft Clarity ──────────────────────────────────────────────────

  window.clarity = window.clarity || noop;

  // ── Mouseflow ──────────────────────────────────────────────────────────

  window.mouseflow = window.mouseflow || {
    start: noop, stop: noop, tag: noop,
    customVariable: noop, pageView: noop,
    identify: noop, addPageTags: noop, setVariable: noop,
  };

  // ── Lucky Orange ───────────────────────────────────────────────────────

  window.__lo_cs_added = true;
  window.__wtw_luckyorange_pp = true;
  window.__wtw_lucky_sites = window.__wtw_lucky_sites || [];
  window.LOQ = window.LOQ || [];
  if (typeof window.LOQ.push !== 'function') { window.LOQ.push = noop; }

  // ── VWO (Visual Website Optimizer) ─────────────────────────────────────

  window._vwo_code = window._vwo_code || { loaded: true, finished: true };
  window.VWO = window.VWO || { push: noop };
  window._vis_opt_account_id = window._vis_opt_account_id || 0;

  // ── Optimizely ─────────────────────────────────────────────────────────

  window.optimizely = window.optimizely || {
    get: function () { return null; },
    push: noop,
    initialized: true,
  };

  // ── Braze / Appboy ─────────────────────────────────────────────────────

  window.appboy = window.appboy || {
    initialize: noop, openSession: noop, changeUser: noop,
    logCustomEvent: noop, logPurchase: noop,
    getUser: function () { return { setFirstName: noopThis, setLastName: noopThis, setEmail: noopThis }; },
    display: { showInAppMessage: noop, showFeed: noop },
  };

})();
