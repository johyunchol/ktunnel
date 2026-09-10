"use strict";

document.addEventListener("submit", function (event) {
  var message = event.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});

function selectText(node) {
  var selection = window.getSelection();
  if (!selection) {
    return;
  }
  var range = document.createRange();
  range.selectNodeContents(node);
  selection.removeAllRanges();
  selection.addRange(range);
}

function fallbackCopy(text, source, trigger) {
  var input = document.createElement("textarea");
  input.value = text;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();

  var copied = false;
  try {
    copied = document.execCommand("copy");
  } catch (_error) {
    copied = false;
  }
  input.remove();
  trigger.focus();

  if (!copied) {
    selectText(source);
  }
  return copied;
}

function copySecret(button) {
  var source = document.getElementById(button.getAttribute("data-copy-target"));
  if (!source) {
    return;
  }

  var text = source.textContent;
  var status = document.getElementById(button.getAttribute("aria-describedby"));
  if (status) {
    status.textContent = "";
  }
  var copy;
  try {
    copy = navigator.clipboard && navigator.clipboard.writeText
      ? navigator.clipboard.writeText(text).catch(function () {
          if (!fallbackCopy(text, source, button)) {
            throw new Error("copy failed");
          }
        })
      : fallbackCopy(text, source, button)
        ? Promise.resolve()
        : Promise.reject(new Error("copy failed"));
  } catch (_error) {
    copy = fallbackCopy(text, source, button)
      ? Promise.resolve()
      : Promise.reject(new Error("copy failed"));
  }

  copy.then(function () {
    var label = button.querySelector("span");
    button.classList.add("is-copied");
    label.textContent = "복사됨";
    if (status) {
      status.textContent = "토큰을 클립보드에 복사했습니다.";
    }
    window.setTimeout(function () {
      button.classList.remove("is-copied");
      label.textContent = button.getAttribute("data-copy-label");
    }, 2000);
  }).catch(function () {
    var label = button.querySelector("span");
    label.textContent = "직접 복사";
    if (status) {
      status.textContent = "자동으로 복사하지 못했습니다. 선택된 토큰을 직접 복사해 주세요.";
    }
  });
}

document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-copy-target]");
  if (button) {
    copySecret(button);
  }
});
