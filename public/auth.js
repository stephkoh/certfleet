// ═══════════════════════════════════════════════════════════════════
// auth.js — session côté navigateur
//
// Le serveur pose un cookie HttpOnly : c'est lui qui fait foi. Le jeton n'est
// conservé en localStorage que pour l'en-tête Authorization, utile si l'API est
// appelée depuis une autre origine. Le profil est mis en cache le temps de la
// page pour ne pas rappeler /api/me à chaque rendu.
// ═══════════════════════════════════════════════════════════════════
(function () {
  const KEY = "certfleet_token";
  const RANK = { viewer: 1, operator: 2, admin: 3 };

  let me = null;

  const esc = (s) => String(s == null ? "" : s)
    .replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  window.CERTFLEET_AUTH = {
    apiBase: "",                       // même origine que la page

    getToken() {
      try { return localStorage.getItem(KEY) || ""; } catch (_) { return ""; }
    },
    setToken(t) {
      try { localStorage.setItem(KEY, t); } catch (_) {}
    },
    headers(extra) {
      const h = Object.assign({}, extra || {});
      const t = this.getToken();
      if (t) h.Authorization = "Bearer " + t;
      return h;
    },

    async logout() {
      try { localStorage.removeItem(KEY); } catch (_) {}
      me = null;
      try { await fetch("/api/logout", { method: "POST", headers: this.headers() }); } catch (_) {}
      location.href = "login.html";
    },

    // Profil de l'utilisateur connecté, ou null. Sert aussi de test de session :
    // un jeton révoqué renvoie 401, et on repart sur la page de connexion.
    async me(opts) {
      if (me && !(opts && opts.force)) return me;
      try {
        const r = await fetch("/api/me", { headers: this.headers() });
        if (!r.ok) return null;
        me = await r.json();
        return me;
      } catch (_) { return null; }
    },

    can(minimum) {
      return (RANK[me && me.role] || 0) >= (RANK[minimum] || 99);
    },

    // À appeler en tête de chaque page protégée. Redirige vers la connexion si
    // la session est tombée, et vers le changement de mot de passe si le compte
    // vient d'être créé ou réinitialisé par un administrateur.
    async guard(opts) {
      const minimum = (opts && opts.minimum) || "viewer";
      const u = await this.me();
      if (!u) { location.href = "login.html"; return null; }

      if (u.must_change_password && !/change-password/.test(location.pathname)) {
        location.href = "change-password.html";
        return null;
      }
      if (!this.can(minimum)) {
        document.body.innerHTML =
          '<div style="font-family:system-ui;padding:48px;max-width:520px;margin:0 auto">' +
          '<h1 style="font-size:19px;margin-bottom:10px">Accès refusé</h1>' +
          '<p style="color:#64748b;font-size:14px;line-height:1.6">Cette page demande le rôle ' +
          "<b>" + esc(minimum) + "</b>. Votre compte a le rôle <b>" + esc(u.role) + "</b>.</p>" +
          '<p style="margin-top:18px"><a href="index.html">← Retour</a></p></div>';
        return null;
      }
      return u;
    },

    // Barre d'identité, commune à toutes les pages.
    renderUserBar(el, user) {
      if (!el || !user) return;
      const label = { admin: "Administrateur", operator: "Opérateur", viewer: "Lecture seule" };
      const color = { admin: "#7c3aed", operator: "#0b3d91", viewer: "#64748b" };

      el.innerHTML =
        '<div style="display:flex;align-items:center;gap:12px;font-size:12.5px">' +
          '<span title="' + esc(user.username) + '" style="width:26px;height:26px;border-radius:50%;' +
            "background:" + (color[user.role] || "#64748b") + ";color:#fff;display:grid;" +
            'place-items:center;font-weight:700;font-size:10.5px">' +
            esc(String(user.display_name || user.username || "?").slice(0, 2).toUpperCase()) +
          "</span>" +
          "<span><b>" + esc(user.display_name || user.username) + "</b>" +
            '<span style="color:#8892a3"> · ' + esc(label[user.role] || user.role) +
            (user.source === "ldap" ? " · annuaire" : "") + "</span></span>" +
          (user.is_admin
            ? '<a href="users.html" style="color:#0b3d91;text-decoration:none;font-weight:600">Comptes</a>'
            : "") +
          '<a href="change-password.html" style="color:#0b3d91;text-decoration:none">Mot de passe</a>' +
          '<a href="#" onclick="CERTFLEET_AUTH.logout();return false" ' +
            'style="color:#dc2626;text-decoration:none">Déconnexion</a>' +
        "</div>";
    },
  };

  // ── Pied de page ────────────────────────────────────────────────────
  // La section 13 de l'AGPL demande qu'une version modifiée propose
  // visiblement son code source aux utilisateurs qui l'atteignent par le
  // réseau. Ce lien rend l'obligation évidente pour qui modifiera certfleet,
  // et signale la licence à ceux qui découvrent l'outil.
  const SOURCE = "https://github.com/stephkoh/certfleet";

  async function injectFooter() {
    if (document.getElementById("cf-footer")) return;

    let version = "";
    try {
      const r = await fetch("/healthz");
      if (r.ok) version = (await r.json()).version || "";
    } catch (_) { /* version simplement omise */ }

    const f = document.createElement("footer");
    f.id = "cf-footer";
    f.style.cssText = "width:100%;text-align:center;padding:18px 12px 22px;" +
      "font-size:11.5px;color:#8892a3;line-height:1.7;font-family:inherit";
    f.innerHTML =
      "<b>certfleet</b>" + (version ? " " + esc(version) : "") +
      ' · <a href="' + SOURCE + '/blob/main/LICENSE" target="_blank" rel="noopener"' +
        ' style="color:#8892a3">AGPL-3.0</a>' +
      ' · <a href="' + SOURCE + '" target="_blank" rel="noopener"' +
        ' style="color:#0b3d91">code source</a>';
    document.body.appendChild(f);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", injectFooter);
  } else {
    injectFooter();
  }
})();
