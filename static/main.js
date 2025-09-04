// static/main.js

document.addEventListener("DOMContentLoaded", () => {
  console.log("CTI Dashboard frontend loaded.");

  // Example: Auto-refresh metrics every 60s
  if (document.querySelector("#dailyChart")) {
    setInterval(() => {
      fetch("/api/metrics")
        .then(r => r.json())
        .then(data => {
          console.log("Metrics refreshed:", data);
        });
    }, 60000);
  }

  // Example: Inline Tag form submission (if used via AJAX)
  const tagForm = document.querySelector("#tagForm");
  if (tagForm) {
    tagForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const value = tagForm.querySelector("[name=value]").value;
      const tag = tagForm.querySelector("[name=tag]").value;
      const res = await fetch("/tag", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `value=${encodeURIComponent(value)}&tag=${encodeURIComponent(tag)}`
      });
      if (res.ok) {
        alert("Tag added!");
        window.location.reload();
      } else {
        alert("Failed to tag IOC.");
      }
    });
  }
});
