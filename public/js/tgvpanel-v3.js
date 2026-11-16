(function () {
  window.hkvmToast = function (message, type) {
    var existing = document.getElementById('hkvmToastContainer');
    if (!existing) {
      existing = document.createElement('div');
      existing.id = 'hkvmToastContainer';
      existing.style.cssText =
        'position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:8px;max-width:380px;';
      document.body.appendChild(existing);
    }
    var el = document.createElement('div');
    var bg =
      type === 'error'
        ? 'rgba(239,68,68,0.95)'
        : type === 'warning'
        ? 'rgba(245,158,11,0.95)'
        : 'rgba(16,185,129,0.95)';
    el.style.cssText =
      'padding:11px 16px;border-radius:10px;color:#fff;font-size:13px;font-weight:500;box-shadow:0 10px 25px rgba(0,0,0,0.35);background:' +
      bg +
      ';';
    el.textContent = message;
    existing.appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 4000);
  };

  window.hkvmApi = async function (url, options) {
    var opts = Object.assign({ method: 'GET', cache: 'no-store', headers: {} }, options || {});
    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta && csrfMeta.content) {
      opts.headers['X-CSRF-Token'] = csrfMeta.content;
    }
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    var res = await fetch(url, opts);
    var data = {};
    try {
      data = await res.json();
    } catch (_e) {
      data = {};
    }
    if (!res.ok) {
      throw new Error(data.error || 'Request failed with HTTP ' + res.status);
    }
    return data;
  };

  window.hkvmRunInstanceAction = async function (engine, id, action, reason) {
    var body = { action: action, async: true };
    if (reason) body.reason = reason;
    var created = await window.hkvmApi('/api/v1/instances/' + encodeURIComponent(engine) + '/' + encodeURIComponent(id) + '/action', {
      method: 'POST',
      body: body
    });
    var taskId = created && created.task && created.task.id;
    if (!taskId) throw new Error('The server did not return a VPS task identifier.');

    var container = document.getElementById('hkvmInstanceTaskContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'hkvmInstanceTaskContainer';
      container.setAttribute('aria-live', 'polite');
      container.setAttribute('aria-label', 'VPS operation progress');
      container.style.cssText = 'position:fixed;top:76px;right:18px;z-index:9998;display:flex;flex-direction:column;gap:8px;width:min(390px,calc(100vw - 36px));';
      document.body.appendChild(container);
    }
    var card = document.createElement('div');
    card.style.cssText = 'background:var(--bg-card,#111827);border:1px solid var(--border-card,#374151);border-radius:10px;padding:12px 14px;color:var(--text-primary,#f9fafb);box-shadow:0 8px 24px rgba(0,0,0,.3);';
    var heading = document.createElement('strong');
    heading.textContent = engine.toUpperCase() + ' #' + id + ' — ' + action;
    var state = document.createElement('div');
    state.style.cssText = 'font-size:12px;color:var(--text-secondary,#9ca3af);margin-top:4px;';
    var step = document.createElement('div');
    step.style.cssText = 'font-size:12px;color:var(--text-muted,#9ca3af);margin-top:3px;';
    var progress = document.createElement('progress');
    progress.max = 100;
    progress.style.cssText = 'width:100%;height:8px;margin-top:8px;';
    card.appendChild(heading);
    card.appendChild(state);
    card.appendChild(step);
    card.appendChild(progress);
    container.appendChild(card);

    var transientFailures = 0;
    while (true) {
      var data;
      try {
        data = await window.hkvmApi('/api/v1/tasks/' + encodeURIComponent(taskId));
        transientFailures = 0;
      } catch (err) {
        transientFailures += 1;
        step.textContent = 'Task status unavailable; the VPS operation may still be running.';
        if (transientFailures >= 5) {
          setTimeout(function () { if (card.parentNode) card.parentNode.removeChild(card); }, 15000);
          throw err;
        }
        await new Promise(function (resolve) { setTimeout(resolve, 1000); });
        continue;
      }
      var task = data.task;
      state.textContent = String(task.status || 'unknown').toUpperCase();
      step.textContent = task.currentStep || 'Waiting for status';
      if (task.progress === null || task.progress === undefined) {
        progress.removeAttribute('value');
      } else {
        progress.value = Number(task.progress);
      }
      if (task.status === 'succeeded') {
        window.hkvmToast('VPS ' + action + ' completed');
        setTimeout(function () { if (card.parentNode) card.parentNode.removeChild(card); }, 8000);
        return task;
      }
      if (task.status === 'failed') {
        setTimeout(function () { if (card.parentNode) card.parentNode.removeChild(card); }, 15000);
        throw new Error(task.error || 'VPS operation failed.');
      }
      await new Promise(function (resolve) { setTimeout(resolve, 800); });
    }
  };

  window.hkvmShowInstanceTaskHistory = async function (engine, id) {
    try {
      var data = await window.hkvmApi('/api/v1/instances/' + encodeURIComponent(engine) + '/' + encodeURIComponent(id) + '/tasks?limit=50');
      var dialog = document.getElementById('hkvmInstanceTaskHistory');
      if (!dialog) {
        dialog = document.createElement('dialog');
        dialog.id = 'hkvmInstanceTaskHistory';
        dialog.style.cssText = 'width:min(760px,calc(100vw - 24px));max-height:80vh;border:1px solid var(--border-card,#374151);border-radius:12px;background:var(--bg-card,#111827);color:var(--text-primary,#f9fafb);padding:18px;';
        document.body.appendChild(dialog);
      }
      dialog.replaceChildren();
      var title = document.createElement('h3');
      title.textContent = engine.toUpperCase() + ' #' + id + ' — Task history';
      var close = document.createElement('button');
      close.type = 'button';
      close.className = 'btn btn-outline';
      close.textContent = 'Close';
      close.style.cssText = 'float:right;';
      close.addEventListener('click', function () { dialog.close(); });
      dialog.appendChild(close);
      dialog.appendChild(title);
      var tasks = data.tasks || [];
      if (!tasks.length) {
        var empty = document.createElement('p');
        empty.textContent = 'No recorded operations for this VPS.';
        dialog.appendChild(empty);
      } else {
        var list = document.createElement('div');
        list.style.cssText = 'display:flex;flex-direction:column;gap:8px;overflow:auto;';
        tasks.forEach(function (task) {
          var item = document.createElement('section');
          item.style.cssText = 'padding:10px;border:1px solid var(--border-subtle,#374151);border-radius:8px;';
          var name = document.createElement('strong');
          name.textContent = String(task.action || 'operation') + ' — ' + String(task.status || 'unknown').toUpperCase();
          var detail = document.createElement('div');
          detail.style.cssText = 'font-size:12px;color:var(--text-secondary,#9ca3af);margin-top:4px;';
          detail.textContent = [task.createdAt, task.currentStep, task.progress == null ? '' : (String(task.progress) + '%')].filter(Boolean).join(' · ');
          item.appendChild(name);
          item.appendChild(detail);
          if (task.error) {
            var error = document.createElement('div');
            error.style.cssText = 'font-size:12px;color:#f87171;margin-top:4px;white-space:pre-wrap;';
            error.textContent = task.error;
            item.appendChild(error);
          }
          list.appendChild(item);
        });
        dialog.appendChild(list);
      }
      if (!dialog.open) dialog.showModal();
    } catch (err) {
      window.hkvmToast(err.message || 'Could not load VPS task history', 'error');
    }
  };

  window.hkvmEsc = function (val) {
    return String(val == null ? '' : val)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  };

  async function refreshHeaderNotifications() {
    var dot = document.getElementById('notifDot');
    var list = document.getElementById('notifList');
    if (!dot || !list) return;
    try {
      var data = await window.hkvmApi('/api/v1/notifications');
      var items = data.notifications || [];
      var unread = items.filter(function (n) {
        return !n.is_read;
      });
      dot.style.display = unread.length > 0 ? 'block' : 'none';
      if (items.length === 0) {
        list.innerHTML =
          '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:12px;">No notifications</div>';
        return;
      }
      list.innerHTML = items
        .slice(0, 10)
        .map(function (n) {
          return (
            '<div style="padding:10px 14px;border-bottom:1px solid var(--border-subtle);opacity:' +
            (n.is_read ? '0.65' : '1') +
            ';">' +
            '<div style="font-size:12px;font-weight:600;color:var(--text-primary);">' +
            window.hkvmEsc(n.title) +
            '</div>' +
            '<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">' +
            window.hkvmEsc(n.message) +
            '</div>' +
            '</div>'
          );
        })
        .join('');
    } catch (_e) {
      // Ignore unauthenticated pages
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    refreshHeaderNotifications();
  });
})();
