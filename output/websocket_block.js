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