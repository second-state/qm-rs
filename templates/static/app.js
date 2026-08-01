// qm-rs client script — rendered by Tera at /assets/app.js.
//
// Two jobs: stream live turn progress into the chat view, and stop a submitted
// composer from being submitted twice.

(function () {
  "use strict";

  function initLiveEvents() {
    var live = document.getElementById("live");
    if (!live || typeof EventSource === "undefined") return;

    var sessionId = live.dataset.session;
    var source = new EventSource("/api/events");

    source.addEventListener("entry", function (message) {
      var event = parse(message);
      if (!event || event.session_id !== sessionId) return;
      live.textContent = describe(event);
    });

    source.addEventListener("done", function (message) {
      var event = parse(message);
      if (!event || event.session_id !== sessionId) return;
      live.textContent = "";
      // The turn finished elsewhere (a cron, Telegram, another tab); reload so
      // the transcript below matches what actually happened.
      if (!document.body.dataset.submitting) window.location.reload();
    });

    source.addEventListener("error", function (message) {
      var event = parse(message);
      if (!event || event.session_id !== sessionId) return;
      live.textContent = "That turn failed: " + (event.text || "unknown error");
    });

    window.addEventListener("beforeunload", function () {
      source.close();
    });
  }

  function parse(message) {
    try {
      return JSON.parse(message.data);
    } catch (e) {
      return null;
    }
  }

  function describe(event) {
    switch (event.entry_type) {
      case "tool_call":
        return "running a tool…";
      case "tool_result":
        return "reading the result…";
      case "thinking":
        return "thinking…";
      case "assistant":
        return "writing a reply…";
      default:
        return "working…";
    }
  }

  function initComposer() {
    var form = document.getElementById("composer");
    if (!form) return;

    var textarea = form.querySelector("textarea");
    var button = form.querySelector("button[type=submit]");

    form.addEventListener("submit", function () {
      document.body.dataset.submitting = "1";
      if (button) {
        button.disabled = true;
        button.textContent = "Working…";
      }
    });

    // Enter submits; Shift+Enter inserts a newline.
    if (textarea) {
      textarea.addEventListener("keydown", function (e) {
        if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
          e.preventDefault();
          if (textarea.value.trim()) form.requestSubmit();
        }
      });
      textarea.focus();
    }
  }

  function initScrollToEnd() {
    var transcript = document.querySelector(".transcript");
    if (!transcript) return;
    var last = transcript.lastElementChild;
    if (last) last.scrollIntoView({ block: "end" });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initLiveEvents();
    initComposer();
    initScrollToEnd();
  });
})();
