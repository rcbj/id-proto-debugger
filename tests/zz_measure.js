const { Builder, By, until } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const base = process.env.BASE || "http://localhost:3200";
const PAGE = process.env.PAGE || "vc-issuance-1.html";
(async () => {
  const o = new chrome.Options();
  o.addArguments("--headless=new", "--no-sandbox", "--disable-dev-shm-usage");
  const d = await new Builder().forBrowser("chrome").setChromeOptions(o).build();
  try {
    await d.manage().window().setRect({ width: 1512, height: 982 });
    await d.get(base + "/" + PAGE);
    await d.wait(until.elementLocated(By.css(".dbg-pane")), 8000);
    await d.sleep(700);
    const r = await d.executeScript(`
      var long = new Array(24).join('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9');
      Array.prototype.slice.call(document.querySelectorAll('.dbg-pane code')).forEach(function (c) {
        if (c.id) c.textContent = long;
      });
      var de = document.documentElement;
      var over = de.scrollWidth - de.clientWidth;
      // Who is actually wider than the viewport?
      var culprits = [];
      Array.prototype.slice.call(document.querySelectorAll('*')).forEach(function (e) {
        var rr = e.getBoundingClientRect();
        if (Math.round(rr.right) > de.clientWidth + 0.5) {
          culprits.push({ tag: e.tagName, id: e.id || '', cls: (e.className||'').toString().slice(0,40),
                          right: Math.round(rr.right), w: Math.round(rr.width) });
        }
      });
      return { client: de.clientWidth, scroll: de.scrollWidth, over: over,
               culprits: culprits.slice(0, 12), total: culprits.length };`);
    console.log("  " + PAGE + ": client=" + r.client + " scroll=" + r.scroll + " OVERFLOW=" + r.over);
    console.log("  elements past the viewport: " + r.total);
    r.culprits.forEach(c => console.log("    " + c.tag + " #" + c.id + " ." + c.cls +
                                        "  right=" + c.right + " width=" + c.w));
  } finally { await d.quit(); }
})();
