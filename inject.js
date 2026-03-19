// Compatibilité Firefox (browser.*) et Chrome (chrome.*)
const _runtime = (typeof browser !== "undefined" && browser.runtime) ? browser.runtime : chrome.runtime;

function injectScript(file_path, tag) {
  var node = document.getElementsByTagName(tag)[0];
  var script = document.createElement("script");
  script.setAttribute("type", "text/javascript");
  script.setAttribute("src", file_path);
  node.appendChild(script);
}

// Inject local forge (cryptographie)
injectScript(_runtime.getURL("forge.min.js"), "body");

// Inject content.js
injectScript(_runtime.getURL("content.js"), "body");
