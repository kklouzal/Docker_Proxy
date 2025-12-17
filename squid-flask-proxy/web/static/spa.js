(() => {
  'use strict';

  const SPA_CONTAINER_ID = 'spa-content';

  const getSpaContainer = (root = document) => root.getElementById(SPA_CONTAINER_ID);

  const isSameOrigin = (url) => {
    try {
      return new URL(url, window.location.href).origin === window.location.origin;
    } catch {
      return false;
    }
  };

  const shouldHandleLinkClick = (event, anchor) => {
    if (!anchor) return false;
    if (event.defaultPrevented) return false;
    if (event.button !== 0) return false;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return false;

    if (anchor.hasAttribute('download')) return false;
    const target = anchor.getAttribute('target');
    if (target && target !== '' && target !== '_self') return false;

    const hrefAttr = anchor.getAttribute('href');
    if (!hrefAttr || hrefAttr.startsWith('mailto:') || hrefAttr.startsWith('tel:')) return false;

    // Only same-origin http(s) navigations.
    const resolved = new URL(anchor.href, window.location.href);
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return false;
    if (resolved.origin !== window.location.origin) return false;

    // Hash-only navigation should behave normally (no fetch).
    const current = new URL(window.location.href);
    if (resolved.pathname === current.pathname && resolved.search === current.search && resolved.hash) {
      return false;
    }

    return true;
  };

  const updateNavActive = (urlString) => {
    const url = new URL(urlString, window.location.href);
    const currentPath = url.pathname;

    const nav = document.querySelector('.nav');
    if (!nav) return;

    const links = Array.from(nav.querySelectorAll('a[href]'));
    links.forEach((a) => a.classList.remove('active'));

    // Mark matching link active (by pathname; query-less nav items in this UI).
    for (const a of links) {
      try {
        const linkUrl = new URL(a.href, window.location.href);
        if (linkUrl.origin === window.location.origin && linkUrl.pathname === currentPath) {
          a.classList.add('active');
        }
      } catch {
        // ignore
      }
    }

    // Dropdown triggers are active when any of their menu links are active.
    const dropdowns = Array.from(nav.querySelectorAll('.nav-dropdown'));
    dropdowns.forEach((dropdown) => {
      const trigger = dropdown.querySelector('.nav-trigger');
      if (!trigger) return;
      const hasActive = Boolean(dropdown.querySelector('.nav-menu a.active'));
      trigger.classList.toggle('active', hasActive);
    });

    // Close any open dropdown after navigation.
    dropdowns.forEach((dropdown) => dropdown.classList.remove('open'));
  };

  const enhanceContainer = (container) => {
    if (!container) return;

    // Squid Config: "Reload from running config" button.
    // This used to live as an inline <script> in the template, which won't execute after SPA swaps.
    const reloadBtn = container.querySelector('#reload-running-config');
    const configTextarea = container.querySelector('#config_text');
    if (reloadBtn && configTextarea && !reloadBtn.dataset.spaBound) {
      reloadBtn.dataset.spaBound = '1';
      reloadBtn.addEventListener('click', async () => {
        const url = reloadBtn.getAttribute('data-url');
        if (!url) return;
        try {
          const response = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const text = await response.text();
          configTextarea.value = text || '';
        } catch (error) {
          // Keep failures silent in UI; log for debugging.
          console.error('Failed to load running config', error);
        }
      });
    }

    // Web Filtering page: bind enable toggle, category tiles, and test-domain button.
    const webfilterEnabledHidden = container.querySelector('#webfilter-enabled-hidden');
    const webfilterEnabledToggle = container.querySelector('#webfilter-enabled-toggle');
    if (webfilterEnabledHidden && webfilterEnabledToggle && !webfilterEnabledToggle.dataset.spaBound) {
      webfilterEnabledToggle.dataset.spaBound = '1';

      const setEnabledTile = (enabled) => {
        webfilterEnabledToggle.classList.toggle('is-enabled', enabled);
        webfilterEnabledToggle.classList.toggle('is-disabled', !enabled);
        webfilterEnabledToggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
        const state = webfilterEnabledToggle.querySelector('.webfilter-toggle-state');
        if (state) state.textContent = enabled ? 'Enabled' : 'Disabled';
      };

      const getEnabledHidden = () => webfilterEnabledHidden.querySelector('input[type="hidden"][name="enabled"][value="on"]');

      webfilterEnabledToggle.addEventListener('click', () => {
        const existing = getEnabledHidden();
        const enabled = !existing;
        if (enabled) {
          const inp = document.createElement('input');
          inp.type = 'hidden';
          inp.name = 'enabled';
          inp.value = 'on';
          webfilterEnabledHidden.appendChild(inp);
        } else if (existing) {
          existing.remove();
        }
        setEnabledTile(enabled);
      });
    }

    const selectedWrap = container.querySelector('#webfilter-selected');
    const tiles = Array.from(container.querySelectorAll('.webfilter-cat'));
    if (selectedWrap && tiles.length > 0) {
      const esc = (s) => (window.CSS && typeof window.CSS.escape === 'function') ? window.CSS.escape(s) : String(s).replace(/"/g, '\\"');
      const getHidden = (cat) => selectedWrap.querySelector(`input[type="hidden"][name="categories"][value="${esc(cat)}"]`);
      const setTile = (tile, blocked) => {
        tile.classList.toggle('is-blocked', blocked);
        tile.classList.toggle('is-allowed', !blocked);
        tile.setAttribute('aria-pressed', blocked ? 'true' : 'false');
      };

      tiles.forEach((tile) => {
        if (tile.dataset.spaBound) return;
        tile.dataset.spaBound = '1';
        const cat = tile.getAttribute('data-category') || '';
        if (!cat) return;
        tile.addEventListener('click', () => {
          const existing = getHidden(cat);
          const blocked = !existing;
          if (blocked) {
            const inp = document.createElement('input');
            inp.type = 'hidden';
            inp.name = 'categories';
            inp.value = cat;
            selectedWrap.appendChild(inp);
          } else {
            existing.remove();
          }
          setTile(tile, blocked);
        });
      });
    }

    const testInp = container.querySelector('#webfilter-test-domain');
    const testBtn = container.querySelector('#webfilter-test-btn');
    const testOut = container.querySelector('#webfilter-test-result');
    if (testInp && testBtn && testOut && !testBtn.dataset.spaBound) {
      testBtn.dataset.spaBound = '1';

      const setResult = (kind, text) => {
        testOut.classList.remove('is-hidden');
        testOut.textContent = text || '';
        testOut.classList.toggle('is-allowed', kind === 'allowed');
        testOut.classList.toggle('is-blocked', kind === 'blocked');
        testOut.classList.toggle('is-neutral', !kind || (kind !== 'allowed' && kind !== 'blocked'));
      };

      testBtn.addEventListener('click', async () => {
        const domain = (testInp.value || '').trim();
        if (!domain) {
          setResult('', 'Enter a domain');
          return;
        }
        setResult('', 'Testing…');
        try {
          const r = await fetch('/webfilter/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
          });
          const data = await r.json();
          const verdict = (data && data.verdict) ? String(data.verdict) : 'error';
          if (verdict === 'blocked') {
            const list = (data && data.matched_blocked && Array.isArray(data.matched_blocked)) ? data.matched_blocked.map(String) : [];
            const by = (data && data.blocked_by) ? String(data.blocked_by) : '';
            const suffix = list.length > 1 ? ` (${list.join(', ')})` : (by ? ` (${by})` : '');
            setResult('blocked', `Blocked${suffix}`);
          } else if (verdict === 'allowed') {
            setResult('allowed', 'Allowed');
          } else if (verdict === 'invalid') {
            setResult('', String(data.reason || 'Invalid domain'));
          } else {
            setResult('', String(data.reason || 'Error'));
          }
        } catch (error) {
          setResult('', 'Error');
        }
      });
    }
  };

  const fetchAndSwap = async (url, { push = true, method = 'GET', body = undefined } = {}) => {
    const container = getSpaContainer();
    if (!container) return false;

    container.setAttribute('aria-busy', 'true');

    try {
      const response = await fetch(url, {
        method,
        body,
        credentials: 'same-origin',
        headers: {
          'X-Requested-With': 'spa',
        },
      });

      if (!response.ok) {
        window.location.assign(url);
        return false;
      }

      const html = await response.text();
      const parsed = new DOMParser().parseFromString(html, 'text/html');
      const nextContainer = getSpaContainer(parsed);

      if (!nextContainer) {
        // Unexpected response shape; fall back to full navigation.
        window.location.assign(response.url || url);
        return false;
      }

      container.innerHTML = nextContainer.innerHTML;
      enhanceContainer(container);

      if (parsed && parsed.title) {
        document.title = parsed.title;
      }

      const finalUrl = response.url || url;
      if (push) {
        window.history.pushState({ url: finalUrl }, '', finalUrl);
      } else {
        window.history.replaceState({ url: finalUrl }, '', finalUrl);
      }

      updateNavActive(finalUrl);
      window.scrollTo(0, 0);
      return true;
    } catch {
      window.location.assign(url);
      return false;
    } finally {
      container.removeAttribute('aria-busy');
    }
  };

  const onDocumentClick = (event) => {
    const anchor = event.target instanceof Element ? event.target.closest('a') : null;
    if (!anchor) return;

    if (!shouldHandleLinkClick(event, anchor)) return;

    const href = anchor.href;
    if (!isSameOrigin(href)) return;

    event.preventDefault();
    void fetchAndSwap(href, { push: true, method: 'GET' });
  };

  const onDocumentSubmit = (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    const container = getSpaContainer();
    if (!container || !container.contains(form)) return;
    if (form.hasAttribute('data-no-spa')) return;

    const action = form.getAttribute('action') || window.location.href;
    if (!isSameOrigin(action)) return;

    const method = (form.getAttribute('method') || 'GET').toUpperCase();

    // Let the browser handle non-GET/POST methods.
    if (method !== 'GET' && method !== 'POST') return;

    event.preventDefault();

    if (method === 'GET') {
      const url = new URL(action, window.location.href);
      const formData = new FormData(form);
      const params = new URLSearchParams();
      for (const [key, value] of formData.entries()) {
        if (typeof value === 'string') params.append(key, value);
      }
      url.search = params.toString();
      void fetchAndSwap(url.toString(), { push: true, method: 'GET' });
      return;
    }

    const body = new FormData(form);
    // For POST, avoid adding noisy history entries; the server usually redirects back.
    void fetchAndSwap(action, { push: false, method: 'POST', body });
  };

  const onPopState = () => {
    void fetchAndSwap(window.location.href, { push: false, method: 'GET' });
  };

  const init = () => {
    // Mark initial nav state based on the current URL (useful after client-side swaps).
    updateNavActive(window.location.href);

    enhanceContainer(getSpaContainer());

    document.addEventListener('click', onDocumentClick, true);
    document.addEventListener('submit', onDocumentSubmit, true);
    window.addEventListener('popstate', onPopState);
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
