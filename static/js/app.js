/* Password Security Analyzer frontend.
   Vanilla JS only. Privacy rules enforced here:
   - POST JSON only, never GET, never URL params.
   - No localStorage / sessionStorage.
   - No console logging of secrets; DOM updated via textContent. */

(function () {
  "use strict";

  var DEBOUNCE_MS = 250;
  var GENERIC_ERROR = "Could not analyze the password. Please try again.";

  var input = document.getElementById("password-input");
  var toggleBtn = document.getElementById("toggle-visibility");
  var clearBtn = document.getElementById("clear-button");
  var meter = document.getElementById("meter");
  var meterFill = document.getElementById("meter-fill");
  var scoreValue = document.getElementById("score-value");
  var strengthLabel = document.getElementById("strength-label");
  var statusLine = document.getElementById("status-line");
  var errorBanner = document.getElementById("error-banner");
  var warningsList = document.getElementById("warnings-list");
  var suggestionsList = document.getElementById("suggestions-list");
  var ringFill = document.getElementById("ring-fill");
  var ringGlow = document.getElementById("ring-glow");
  var ringWrap = document.getElementById("ring-wrap");
  var scoreBig = document.getElementById("score-big");
  var ringSub = document.getElementById("ring-sub");
  var statLength = document.getElementById("stat-length");
  var statVariety = document.getElementById("stat-variety");
  var statEntropy = document.getElementById("stat-entropy");
  var statRisk = document.getElementById("stat-risk");
  var statUnique = document.getElementById("stat-unique");
  var RING_C = 2 * Math.PI * 88;

  var checks = {
    length: document.getElementById("check-length"),
    upper: document.getElementById("check-upper"),
    lower: document.getElementById("check-lower"),
    digit: document.getElementById("check-digit"),
    special: document.getElementById("check-special")
  };

  var debounceTimer = null;
  var abortController = null;

  function strengthClass(strength) {
    switch (strength) {
      case "Very Weak": return "strength-very-weak";
      case "Weak": return "strength-weak";
      case "Moderate": return "strength-moderate";
      case "Strong": return "strength-strong";
      case "Very Strong": return "strength-very-strong";
      default: return "strength-idle";
    }
  }

  function setCheck(el, passed) {
    if (!el) return;
    el.classList.remove("idle", "pass", "fail");
    el.classList.add(passed ? "pass" : "fail");
    var icon = el.querySelector(".check-icon");
    if (icon) icon.textContent = passed ? "✓" : "✗";
  }

  function setCheckIdle(el) {
    if (!el) return;
    el.classList.remove("pass", "fail");
    el.classList.add("idle");
    var icon = el.querySelector(".check-icon");
    if (icon) icon.textContent = "○";
  }

  function clearList(ul) {
    while (ul.firstChild) ul.removeChild(ul.firstChild);
  }

  function addListItem(ul, text, muted) {
    var li = document.createElement("li");
    li.textContent = text;
    if (muted) li.classList.add("muted");
    ul.appendChild(li);
  }

  function tierKey(strength) {
    switch (strength) {
      case "Very Weak": return "very-weak";
      case "Weak": return "weak";
      case "Moderate": return "moderate";
      case "Strong": return "strong";
      case "Very Strong": return "very-strong";
      default: return "idle";
    }
  }

  function renderMeter(score, strength) {
    scoreValue.textContent = score + " / 100";
    strengthLabel.textContent = strength;
    strengthLabel.className = "strength-pill " + strengthClass(strength);
    meterFill.style.width = score + "%";
    meter.setAttribute("aria-valuenow", String(score));
    statusLine.textContent = "Score " + score + " of 100: " + strength + ".";
    var offset = RING_C * (1 - score / 100);
    if (ringFill) ringFill.style.strokeDashoffset = String(offset);
    if (ringGlow) ringGlow.style.strokeDashoffset = String(offset);
    if (ringWrap) ringWrap.setAttribute("data-tier", tierKey(strength));
    if (scoreBig) scoreBig.textContent = String(score);
    if (ringSub) ringSub.textContent = String(strength).toUpperCase();
  }

  function renderCoreStats(checks, warnings, score) {
    var len = checks && typeof checks.length === "number" ? checks.length : 0;
    var classes = ["has_upper", "has_lower", "has_digit", "has_special"]
      .filter(function (k) { return checks && checks[k]; }).length;
    if (statLength) statLength.textContent = len + (len === 1 ? " char" : " chars");
    if (statVariety) statVariety.textContent = classes + "/4 classes · " + len + " len";
    if (statEntropy) {
      statEntropy.textContent = score >= 80 ? "High" : score >= 60 ? "Good" : score >= 40 ? "Fair" : score > 0 ? "Low" : "—";
    }
    if (statRisk) {
      var w = (warnings || []).filter(function (x) { return x !== "No major weaknesses detected."; }).length;
      statRisk.textContent = w === 0 ? (score > 0 ? "Clean" : "—") : w + (w === 1 ? " flag" : " flags");
    }
    if (statUnique) statUnique.textContent = classes >= 4 ? "Max" : classes >= 3 ? "High" : classes >= 2 ? "Med" : classes >= 1 ? "Low" : "—";
  }

  function renderChecks(apiChecks) {
    setCheck(checks.length, Boolean(apiChecks.min_length_12));
    setCheck(checks.upper, Boolean(apiChecks.has_upper));
    setCheck(checks.lower, Boolean(apiChecks.has_lower));
    setCheck(checks.digit, Boolean(apiChecks.has_digit));
    setCheck(checks.special, Boolean(apiChecks.has_special));
  }

  function renderWarnings(warnings) {
    clearList(warningsList);
    if (!warnings || warnings.length === 0) {
      addListItem(warningsList, "No major weaknesses detected.", true);
      return;
    }
    warnings.forEach(function (w) { addListItem(warningsList, w, false); });
  }

  function renderSuggestions(suggestions) {
    clearList(suggestionsList);
    if (!suggestions || suggestions.length === 0) {
      addListItem(suggestionsList, "Your password meets the recommended criteria.", true);
      return;
    }
    suggestions.forEach(function (s) { addListItem(suggestionsList, s, false); });
  }

  function setLoading() {
    errorBanner.hidden = true;
    errorBanner.textContent = "";
    meter.classList.add("loading");
    statusLine.textContent = "Analyzing…";
  }

  function setError() {
    meter.classList.remove("loading");
    errorBanner.textContent = GENERIC_ERROR;
    errorBanner.hidden = false;
    statusLine.textContent = "Analysis failed.";
  }

  function resetUI() {
    if (abortController) {
      abortController.abort();
      abortController = null;
    }
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    errorBanner.hidden = true;
    errorBanner.textContent = "";
    meter.classList.remove("loading");
    meterFill.style.width = "0%";
    meter.setAttribute("aria-valuenow", "0");
    scoreValue.textContent = "– / 100";
    strengthLabel.textContent = "Awaiting input";
    strengthLabel.className = "strength-pill strength-idle";
    statusLine.textContent = "Awaiting input.";
    if (ringFill) ringFill.style.strokeDashoffset = String(RING_C);
    if (ringGlow) ringGlow.style.strokeDashoffset = String(RING_C);
    if (ringWrap) ringWrap.setAttribute("data-tier", "idle");
    if (scoreBig) scoreBig.textContent = "–";
    if (ringSub) ringSub.textContent = "STANDBY";
    if (statLength) statLength.textContent = "0 chars";
    if (statVariety) statVariety.textContent = "— classes";
    if (statEntropy) statEntropy.textContent = "—";
    if (statRisk) statRisk.textContent = "—";
    if (statUnique) statUnique.textContent = "—";
    Object.keys(checks).forEach(function (k) { setCheckIdle(checks[k]); });
    clearList(warningsList);
    addListItem(warningsList, "Enter a password to begin.", true);
    clearList(suggestionsList);
    addListItem(suggestionsList, "Recommendations will appear here.", true);
  }

  function analyzePassword() {
    var value = input.value;
    if (!value) {
      resetUI();
      return;
    }
    setLoading();

    if (abortController) abortController.abort();
    abortController = new AbortController();

    fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: value }),
      signal: abortController.signal
    })
      .then(function (res) {
        if (!res.ok) throw new Error("request failed");
        return res.json();
      })
      .then(function (data) {
        meter.classList.remove("loading");
        errorBanner.hidden = true;
        renderMeter(data.score, data.strength);
        renderChecks(data.checks || {});
        renderWarnings(data.warnings || []);
        renderSuggestions(data.suggestions || []);
        renderCoreStats(data.checks || {}, data.warnings || [], data.score);
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") return;
        setError();
      });
  }

  input.addEventListener("input", function () {
    if (statLength) {
      var n = input.value.length;
      statLength.textContent = n + (n === 1 ? " char" : " chars");
    }
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(analyzePassword, DEBOUNCE_MS);
  });

  toggleBtn.addEventListener("click", function () {
    var showing = input.type === "text";
    input.type = showing ? "password" : "text";
    toggleBtn.setAttribute("aria-pressed", showing ? "false" : "true");
    toggleBtn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    input.focus();
  });

  clearBtn.addEventListener("click", function () {
    input.value = "";
    resetUI();
    input.focus();
  });

  resetUI();
})();
