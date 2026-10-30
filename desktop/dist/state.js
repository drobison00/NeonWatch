// The app's own page: what it shows while it connects, and when the service is not running.
// The app opens it with ?state=connecting|down&reason=…; its buttons are neonwatch-action:
// links the app intercepts, so this page needs no IPC.
(() => {
  const q = new URLSearchParams(location.search);
  const state = q.get("state") || "connecting";
  const $ = (id) => document.getElementById(id);
  if (state === "down") {
    $("message").textContent = "The NeonWatch service is not running.";
    $("detail").textContent = q.get("reason") || "";
    $("actions").hidden = false;
    $("help").hidden = false;
  } else if (state === "starting") {
    $("message").textContent = "Starting the service…";
  }
  $("retry").addEventListener("click", () => { $("message").textContent = "Connecting to the dashboard…"; });
  $("start").addEventListener("click", () => { $("message").textContent = "Starting the service…"; });
})();
