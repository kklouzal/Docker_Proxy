(() => {
  'use strict';

  const SPA_CONTAINER_ID = 'spa-content';
  const SHELL_SELECTORS = {
    header: '#site-header',
    context: '#context-strip-slot',
  };
  const DESKTOP_NAV_MEDIA = '(min-width: 1101px)';
  let shellListenersBound = false;
  let currentSpaUrl = window.location.href;
  let unsavedConfigChanges = false;
  const UNSAVED_CONFIG_MESSAGE = 'You have unsaved Squid configuration changes. Leave this page anyway?';

  const getCsrfToken = () => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? (meta.getAttribute('content') || '') : '';
  };

  const getAssetVersion = (root = document) => {
    const meta = root.querySelector('meta[name="asset-version"]');
    return meta ? (meta.getAttribute('content') || '') : '';
  };

  const setCsrfToken = (value) => {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) {
      meta.setAttribute('content', value || '');
    }
  };

  const getSpaContainer = (root = document) => root.getElementById(SPA_CONTAINER_ID);

  const getHeader = () => document.querySelector('.site-header');

  const closeHeaderDropdowns = () => {
    const header = getHeader();
    if (!header) return;
    header.querySelectorAll('.nav-dropdown.open').forEach((dropdown) => {
      dropdown.classList.remove('open');
      const trigger = dropdown.querySelector('.nav-trigger');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
  };

  const setHeaderMenuOpen = (open) => {
    const header = getHeader();
    if (!header) return;
    header.classList.toggle('menu-open', Boolean(open));
    const toggle = header.querySelector('#nav-toggle');
    if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  };

  const setUnsavedConfigChanges = (active) => {
    unsavedConfigChanges = Boolean(active);
  };

  const confirmDiscardUnsavedConfigChanges = () => {
    if (!unsavedConfigChanges) return true;
    return window.confirm(UNSAVED_CONFIG_MESSAGE);
  };

  const setTransientButtonLabel = (button, label) => {
    if (!(button instanceof HTMLButtonElement)) return;
    if (!button.dataset.originalLabel) {
      button.dataset.originalLabel = button.textContent || '';
    }
    if (button.dataset.labelTimer) {
      window.clearTimeout(Number(button.dataset.labelTimer));
      delete button.dataset.labelTimer;
    }
    button.textContent = label;
    button.dataset.labelTimer = String(window.setTimeout(() => {
      button.textContent = button.dataset.originalLabel || '';
      delete button.dataset.labelTimer;
    }, 1600));
  };

  const copyTextToClipboard = async (text) => {
    const payload = String(text || '');
    if (!payload) return false;

    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(payload);
        return true;
      }
    } catch {
      // Fall through to legacy clipboard handling.
    }

    const temp = document.createElement('textarea');
    temp.value = payload;
    temp.setAttribute('readonly', 'readonly');
    temp.style.position = 'fixed';
    temp.style.opacity = '0';
    temp.style.pointerEvents = 'none';
    document.body.appendChild(temp);
    temp.focus();
    temp.select();
    try {
      return document.execCommand('copy');
    } catch {
      return false;
    } finally {
      temp.remove();
    }
  };

  const getTrackableFormControls = (form) => Array.from(form.elements).filter((element) => {
    if (!(element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement)) {
      return false;
    }
    if (!element.name) return false;
    if (element instanceof HTMLInputElement && ['hidden', 'submit', 'button', 'reset', 'image', 'file'].includes(element.type)) {
      return false;
    }
    return true;
  });

  const serializeControlValue = (control) => {
    if (control instanceof HTMLInputElement && (control.type === 'checkbox' || control.type === 'radio')) {
      return control.checked ? 'checked' : 'unchecked';
    }
    return String(control.value || '');
  };

  const enhanceConfigPage = (container) => {
    const configPage = container.querySelector('[data-config-page="true"]');
    if (!configPage) {
      setUnsavedConfigChanges(false);
      return;
    }

    const getTargetsForForm = (attrName, formId) => Array.from(configPage.querySelectorAll(`[${attrName}]`))
      .filter((element) => element.getAttribute(attrName) === formId);

    configPage.querySelectorAll('[data-copy-target]').forEach((button) => {
      if (!(button instanceof HTMLButtonElement) || button.dataset.spaBound === '1') return;
      button.dataset.spaBound = '1';
      button.addEventListener('click', async () => {
        const selector = button.getAttribute('data-copy-target') || '';
        if (!selector) return;
        const source = configPage.querySelector(selector) || document.querySelector(selector);
        if (!(source instanceof HTMLInputElement || source instanceof HTMLTextAreaElement || source instanceof HTMLElement)) return;
        const text = source instanceof HTMLInputElement || source instanceof HTMLTextAreaElement
          ? source.value
          : (source.textContent || '');
        const ok = await copyTextToClipboard(text);
        setTransientButtonLabel(button, ok ? 'Copied' : 'Copy failed');
      });
    });

    const forms = Array.from(configPage.querySelectorAll('form[data-config-form]')).filter((form) => form instanceof HTMLFormElement);
    if (!forms.length) {
      setUnsavedConfigChanges(false);
      return;
    }

    const formDirtyCounts = new Map();

    const syncPageDirtyState = () => {
      const totalDirty = Array.from(formDirtyCounts.values()).reduce((sum, count) => sum + count, 0);
      const isDirty = totalDirty > 0;
      configPage.dataset.dirty = isDirty ? 'true' : 'false';
      setUnsavedConfigChanges(isDirty);
    };

    forms.forEach((form) => {
      if (!form.id) return;

      const controls = getTrackableFormControls(form);
      const initialValues = new Map(controls.map((control) => [control, serializeControlValue(control)]));
      const dependencyFields = Array.from(configPage.querySelectorAll('.config-field[data-config-form-owner]'))
        .filter((field) => field.getAttribute('data-config-form-owner') === form.id && field.hasAttribute('data-depends-on'));

      const dirtyIndicators = getTargetsForForm('data-config-dirty-indicator-for', form.id);
      const dirtyCounts = getTargetsForForm('data-config-dirty-count-for', form.id);
      const metricTargets = getTargetsForForm('data-config-metrics-for', form.id);
      const resetButtons = getTargetsForForm('data-config-reset-for', form.id).filter((button) => button instanceof HTMLButtonElement);

      const getControlByName = (name) => Array.from(form.elements).find((element) => {
        if (!(element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement)) {
          return false;
        }
        return element.name === name;
      });

      const dependencyMatches = (control, expected) => {
        const expectation = String(expected || '').trim().toLowerCase();
        if (!expectation) return true;

        if (control instanceof HTMLInputElement && (control.type === 'checkbox' || control.type === 'radio')) {
          if (expectation === 'checked' || expectation === 'true' || expectation === 'on') return control.checked;
          if (expectation === 'unchecked' || expectation === 'false' || expectation === 'off') return !control.checked;
        }

        const value = String(control.value || '').trim().toLowerCase();
        if (expectation === 'blank') return value === '';
        if (expectation === 'nonblank') return value !== '';
        return value === expectation;
      };

      const applyDependencies = () => {
        dependencyFields.forEach((field) => {
          const dependsOn = (field.getAttribute('data-depends-on') || '').split(',').map((value) => value.trim()).filter(Boolean);
          const showWhen = (field.getAttribute('data-show-when') || '').split(',').map((value) => value.trim());
          const visible = dependsOn.every((name, index) => {
            const control = getControlByName(name);
            if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement)) {
              return true;
            }
            return dependencyMatches(control, showWhen[index] || 'checked');
          });

          field.classList.toggle('is-hidden', !visible);
          field.classList.toggle('is-disabled', !visible);
          field.querySelectorAll('input, select, textarea').forEach((control) => {
            if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement)) {
              return;
            }
            control.disabled = !visible;
          });
        });
      };

      const updateMetrics = () => {
        if (!metricTargets.length) return;
        const textControl = controls.find((control) => control.name === 'config_text');
        const text = textControl ? String(textControl.value || '') : '';
        const lineCount = text ? text.split(/\r?\n/).length : 0;
        const charCount = text.length;
        metricTargets.forEach((target) => {
          target.textContent = `${lineCount} line${lineCount === 1 ? '' : 's'} · ${charCount} char${charCount === 1 ? '' : 's'}`;
        });
      };

      const recompute = () => {
        applyDependencies();
        updateMetrics();

        let dirtyCount = 0;
        controls.forEach((control) => {
          const wrapper = control.closest('.config-field');
          const isVisible = !control.disabled && (!wrapper || !wrapper.classList.contains('is-hidden'));
          const isDirty = isVisible && serializeControlValue(control) !== initialValues.get(control);
          if (wrapper) {
            wrapper.classList.toggle('is-dirty', isDirty);
          }
          if (isDirty) dirtyCount += 1;
        });

        dirtyIndicators.forEach((indicator) => {
          indicator.textContent = dirtyCount ? 'Unsaved changes' : 'No local changes';
          indicator.classList.toggle('ok', dirtyCount === 0);
          indicator.classList.toggle('warn', dirtyCount > 0);
          indicator.classList.remove('danger');
        });

        dirtyCounts.forEach((target) => {
          target.textContent = `${dirtyCount} pending change${dirtyCount === 1 ? '' : 's'}`;
        });

        resetButtons.forEach((button) => {
          button.disabled = dirtyCount === 0;
        });

        formDirtyCounts.set(form.id, dirtyCount);
        syncPageDirtyState();
      };

      controls.forEach((control) => {
        if (control.dataset.spaBound === '1') return;
        control.dataset.spaBound = '1';
        control.addEventListener('input', recompute);
        control.addEventListener('change', recompute);
      });

      resetButtons.forEach((button) => {
        if (button.dataset.spaBound === '1') return;
        button.dataset.spaBound = '1';
        button.addEventListener('click', () => {
          form.reset();
          window.requestAnimationFrame(recompute);
        });
      });

      if (form.dataset.spaBound !== '1') {
        form.dataset.spaBound = '1';
        form.addEventListener('submit', () => {
          configPage.dataset.dirty = 'false';
          setUnsavedConfigChanges(false);
        });
      }

      recompute();
    });

    syncPageDirtyState();
  };

  const focusPageHeading = (container) => {
    if (!container) return;
    const heading = container.querySelector('.page-title');
    if (!(heading instanceof HTMLElement)) return;
    if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
    heading.focus({ preventScroll: true });
  };

  const syncShellFromDocument = (parsed) => {
    const nextHeader = parsed.querySelector(SHELL_SELECTORS.header);
    const currentHeader = document.querySelector(SHELL_SELECTORS.header);
    if (currentHeader && nextHeader) {
      currentHeader.replaceWith(nextHeader);
    }

    const nextContext = parsed.querySelector(SHELL_SELECTORS.context);
    const currentContext = document.querySelector(SHELL_SELECTORS.context);
    if (currentContext && nextContext) {
      currentContext.innerHTML = nextContext.innerHTML;
    }

    const nextMeta = parsed.querySelector('meta[name="csrf-token"]');
    if (nextMeta) {
      setCsrfToken(nextMeta.getAttribute('content') || '');
    }

    if (parsed.body) {
      document.body.dataset.activeProxyId = parsed.body.dataset.activeProxyId || '';
    }

    bindShell();
  };

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
    links.forEach((a) => {
      a.classList.remove('active');
      a.removeAttribute('aria-current');
    });

    // Mark matching link active (by pathname; query-less nav items in this UI).
    for (const a of links) {
      try {
        const linkUrl = new URL(a.href, window.location.href);
        if (linkUrl.origin === window.location.origin && linkUrl.pathname === currentPath) {
          a.classList.add('active');
          a.setAttribute('aria-current', 'page');
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
    dropdowns.forEach((dropdown) => {
      dropdown.classList.remove('open');
      const trigger = dropdown.querySelector('.nav-trigger');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
    setHeaderMenuOpen(false);
  };

  const bindShell = () => {
    const header = getHeader();
    if (!header || header.dataset.spaBound === '1') return;
    header.dataset.spaBound = '1';

    const closeTimers = new WeakMap();
    const dropdowns = Array.from(header.querySelectorAll('.nav-dropdown'));
    const navToggle = header.querySelector('#nav-toggle');

    const clearCloseTimer = (dropdown) => {
      const timer = closeTimers.get(dropdown);
      if (timer) {
        window.clearTimeout(timer);
        closeTimers.delete(dropdown);
      }
    };

    const closeDropdown = (dropdown) => {
      clearCloseTimer(dropdown);
      dropdown.classList.remove('open');
      const trigger = dropdown.querySelector('.nav-trigger');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    };

    const openDropdown = (dropdown) => {
      dropdowns.forEach((item) => {
        if (item !== dropdown) closeDropdown(item);
      });
      clearCloseTimer(dropdown);
      dropdown.classList.add('open');
      const trigger = dropdown.querySelector('.nav-trigger');
      if (trigger) trigger.setAttribute('aria-expanded', 'true');
    };

    const scheduleClose = (dropdown) => {
      clearCloseTimer(dropdown);
      const timer = window.setTimeout(() => closeDropdown(dropdown), 240);
      closeTimers.set(dropdown, timer);
    };

    dropdowns.forEach((dropdown) => {
      const trigger = dropdown.querySelector('.nav-trigger');
      if (trigger && trigger.dataset.spaBound !== '1') {
        trigger.dataset.spaBound = '1';
        trigger.addEventListener('click', (event) => {
          event.preventDefault();
          const isOpen = dropdown.classList.contains('open');
          if (isOpen) {
            closeDropdown(dropdown);
          } else {
            openDropdown(dropdown);
          }
        });
      }

      dropdown.addEventListener('mouseenter', () => {
        if (window.matchMedia(DESKTOP_NAV_MEDIA).matches) {
          openDropdown(dropdown);
        }
      });
      dropdown.addEventListener('mouseleave', () => {
        if (window.matchMedia(DESKTOP_NAV_MEDIA).matches) {
          scheduleClose(dropdown);
        }
      });
    });

    if (navToggle && navToggle.dataset.spaBound !== '1') {
      navToggle.dataset.spaBound = '1';
      navToggle.addEventListener('click', () => {
        const shouldOpen = !header.classList.contains('menu-open');
        setHeaderMenuOpen(shouldOpen);
        if (!shouldOpen) closeHeaderDropdowns();
      });
      setHeaderMenuOpen(header.classList.contains('menu-open'));
    }

    if (!shellListenersBound) {
      shellListenersBound = true;

      document.addEventListener('click', (event) => {
        const headerEl = getHeader();
        if (!headerEl || !(event.target instanceof Element)) return;
        if (!headerEl.contains(event.target)) {
          closeHeaderDropdowns();
          setHeaderMenuOpen(false);
        }
      }, true);

      document.addEventListener('keydown', (event) => {
        if (event.key !== 'Escape') return;
        closeHeaderDropdowns();
        setHeaderMenuOpen(false);
      });

      window.addEventListener('resize', () => {
        if (window.matchMedia(DESKTOP_NAV_MEDIA).matches) {
          setHeaderMenuOpen(false);
        }
      });
    }
  };

  const enhanceContainer = (container) => {
    if (!container) return;

    const heading = container.querySelector('.page-title');
    if (heading && !heading.hasAttribute('tabindex')) {
      heading.setAttribute('tabindex', '-1');
    }

    enhanceConfigPage(container);

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
          configTextarea.dispatchEvent(new Event('input', { bubbles: true }));
          configTextarea.dispatchEvent(new Event('change', { bubbles: true }));
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
      const testUrl = testBtn.getAttribute('data-url') || '/webfilter/test';

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
          const r = await fetch(testUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': getCsrfToken(),
            },
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
      const headers = {
        'X-Requested-With': 'spa',
      };
      if (method && String(method).toUpperCase() !== 'GET') {
        headers['X-CSRF-Token'] = getCsrfToken();
      }

      const response = await fetch(url, {
        method,
        body,
        credentials: 'same-origin',
        headers,
      });

      if (!response.ok) {
        window.location.assign(url);
        return false;
      }

      const html = await response.text();
      const parsed = new DOMParser().parseFromString(html, 'text/html');
      const nextContainer = getSpaContainer(parsed);
      const nextAssetVersion = getAssetVersion(parsed);
      const currentAssetVersion = getAssetVersion(document);

      if (nextAssetVersion && nextAssetVersion !== currentAssetVersion) {
        window.location.assign(response.url || url);
        return false;
      }

      if (!nextContainer) {
        // Unexpected response shape; fall back to full navigation.
        window.location.assign(response.url || url);
        return false;
      }

      syncShellFromDocument(parsed);
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
      currentSpaUrl = finalUrl;

      updateNavActive(finalUrl);
      window.scrollTo(0, 0);
      focusPageHeading(container);
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
    if (!confirmDiscardUnsavedConfigChanges()) return;

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

    if (form.dataset.allowDirtySubmit !== '1' && !confirmDiscardUnsavedConfigChanges()) {
      return;
    }

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
    if (!confirmDiscardUnsavedConfigChanges()) {
      window.history.pushState({ url: currentSpaUrl }, '', currentSpaUrl);
      return;
    }
    void fetchAndSwap(window.location.href, { push: false, method: 'GET' });
  };

  const init = () => {
    // Mark initial nav state based on the current URL (useful after client-side swaps).
    currentSpaUrl = window.location.href;
    if (!window.history.state || !window.history.state.url) {
      window.history.replaceState({ url: currentSpaUrl }, '', currentSpaUrl);
    }
    bindShell();
    updateNavActive(window.location.href);

    enhanceContainer(getSpaContainer());

    document.addEventListener('click', onDocumentClick, true);
    document.addEventListener('submit', onDocumentSubmit, true);
    window.addEventListener('popstate', onPopState);
    window.addEventListener('beforeunload', (event) => {
      if (!unsavedConfigChanges) return;
      event.preventDefault();
      event.returnValue = '';
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
