// Emerald Ad Blocker — websocket_block.js
// Injected by WKUserScript at document_start.
// Blocks WebSocket connections to known trackers and prevents WebRTC IP leaks.
(function () {
  'use strict';

  // ── WebSocket blocking ────────────────────────────────────────────────────

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

  window.WebSocket = function (url, protocols) {
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
  window.WebSocket.prototype = _WS.prototype;
  window.WebSocket.CONNECTING = 0;
  window.WebSocket.OPEN = 1;
  window.WebSocket.CLOSING = 2;
  window.WebSocket.CLOSED = 3;

  // ── WebRTC IP leak prevention ─────────────────────────────────────────────

  var _RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
  if (_RTC) {
    window.RTCPeerConnection = function (config, constraints) {
      if (config && config.iceServers) {
        config.iceServers = [];
      }
      return new _RTC(config, constraints);
    };
    window.RTCPeerConnection.prototype = _RTC.prototype;
    if (window.webkitRTCPeerConnection) {
      window.webkitRTCPeerConnection = window.RTCPeerConnection;
    }
  }

  // ── navigator.sendBeacon blocking ─────────────────────────────────────────

  var _beacon = navigator.sendBeacon;
  var BLOCKED_BEACON = [
    /google-analytics/i, /doubleclick/i, /facebook/i,
    /analytics/i, /collect/i, /pixel/i, /beacon/i,
  ];

  if (_beacon) {
    navigator.sendBeacon = function (url) {
      var urlStr = String(url);
      for (var i = 0; i < BLOCKED_BEACON.length; i++) {
        if (BLOCKED_BEACON[i].test(urlStr)) return true; // pretend success
      }
      return _beacon.apply(navigator, arguments);
    };
  }

})();
