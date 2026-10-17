// the language first: English is in the code, another language is a dictionary i18n/<code>.json (none = English);
// the saved choice, else the browser's language; then the app
(function () {
  let l = ''; try { l = localStorage.getItem('ft-lang') || ''; } catch (e) {}
  if (!/^[a-z]{2,3}$/.test(l)) l = (navigator.language || 'en').slice(0, 2).toLowerCase();
  const start = (lang, dict) => { window.FT_LANG = lang; window.FT_DICT = dict;
    const s = document.createElement('script'); s.src = 'app.js'; document.body.appendChild(s); };
  if (!/^[a-z]{2,3}$/.test(l) || l === 'en') return start('en', {});
  fetch(`i18n/${l}.json`, {cache: 'no-cache'}).then(r => r.ok ? r.json() : null).catch(() => null)
    .then(d => d ? start(l, d) : start('en', {}));
})();
