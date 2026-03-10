(function (globalScope) {
  function normalizeLanguage(lang) {
    return lang === "th" ? "th" : "en";
  }

  async function loadLocale(lang, cache) {
    const normalized = normalizeLanguage(lang);
    if (cache[normalized]) return cache[normalized];

    try {
      const url = chrome.runtime.getURL(`i18n/${normalized}.json`);
      const response = await fetch(url);
      if (!response.ok) throw new Error(`Failed to load ${normalized}.json`);
      cache[normalized] = await response.json();
    } catch (error) {
      console.error("Language load failed:", error);
      cache[normalized] = {};
    }

    return cache[normalized];
  }

  async function preloadLocales(languages, cache) {
    await Promise.all(languages.map((lang) => loadLocale(lang, cache)));
  }

  globalScope.ThreatMagnifierI18n = {
    normalizeLanguage,
    loadLocale,
    preloadLocales,
  };
})(self);
