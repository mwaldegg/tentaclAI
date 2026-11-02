"""svc web: web sources as readable text, links or raw HTML, with a login."""
import os
import re
import subprocess
import sys
from html.parser import HTMLParser

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import api_part, core, gate, safeguards


# ---------- web sources (web) ----------

class _HTMLText(HTMLParser):
    """small HTML → markdown-ish text converter (headings, paragraphs, lists, links, code)"""
    SKIP = {"script", "style", "noscript", "svg", "template", "head"}
    BLOCK = {"p", "div", "section", "article", "main", "header", "footer", "table", "tr", "br", "hr", "form", "blockquote", "dl", "dt", "dd"}

    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
    HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])|opacity\s*:\s*0(?![.\d]*[1-9])", re.I)

    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.out, self.skip, self.links, self.title, self._title, self._href, self._pre = base, [], 0, [], "", False, None, 0
        self.hidden, self._stack, self._hdepth, self.hidden_text = 0, [], 0, []  # hidden elements: a reader doesn't see them

    def _is_hidden(self, a):
        return ("hidden" in a or (a.get("aria-hidden") or "").lower() == "true"
                or bool(self.HIDDEN_STYLE.search(a.get("style") or "")))

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag not in self.VOID:
            hide = self._is_hidden(a)
            self._stack.append((tag, hide))
            if hide:
                self.hidden += 1
                self._hdepth += 1
                self.skip += 1
                return
        if tag in self.SKIP:
            self.skip += 1
        elif tag == "title":
            self._title = True
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self.out.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag == "li":
            self.out.append("\n- ")
        elif tag in ("td", "th"):
            self.out.append(" | ")
        elif tag == "pre":
            self._pre += 1
            self.out.append("\n```\n")
        elif tag == "code" and not self._pre:
            self.out.append("`")
        elif tag == "a" and a.get("href"):
            from urllib.parse import urljoin
            self._href = urljoin(self.base, a["href"])
            self.out.append("[")
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag not in self.VOID and any(t == tag for t, _ in self._stack):
            while self._stack:  # close up to the matching tag (HTML often leaves inner tags open)
                t, hide = self._stack.pop()
                if hide:
                    self.skip = max(0, self.skip - 1)
                    self._hdepth = max(0, self._hdepth - 1)
                if t == tag:
                    break
            if hide and t == tag:
                return
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag == "title":
            self._title = False
        elif tag == "pre":
            self._pre = max(0, self._pre - 1)
            self.out.append("\n```\n")
        elif tag == "code" and not self._pre:
            self.out.append("`")
        elif tag == "a" and self._href:
            self.out.append(f"]({self._href})")
            self.links.append(self._href)
            self._href = None
        elif tag in self.BLOCK or tag in ("h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol"):
            self.out.append("\n")

    def handle_data(self, data):
        if self._title:
            self.title += data
        if self._hdepth:
            self.hidden_text.append(data)
        if self.skip:
            return
        self.out.append(data if self._pre else re.sub(r"\s+", " ", data))

    def text(self):
        t = "".join(self.out)
        t = re.sub(r"[ \t]+\n", "\n", t)
        return re.sub(r"\n{3,}", "\n\n", t).strip()


def web_paths(name):
    """the service's cookie jar – in the home of its user, created and used by it (it runs curl)"""
    pw = core.run_account(name)
    jar = os.path.join(pw.pw_dir if pw else os.path.expanduser("~"), ".cache", "tentaclai", "web", f"{name}.cookies")
    subprocess.run(["sh", "-c", 'umask 077; mkdir -p "$(dirname "$1")" && touch "$1"', "sh", jar], **core.runner(name))
    return jar


def web_url(name, web, path):
    from urllib.parse import urlparse
    base = web["base_url"].rstrip("/")
    url = path if path.startswith(("http://", "https://")) else base + "/" + path.lstrip("/")
    b, u = urlparse(base), urlparse(url)
    if (u.scheme, u.netloc) != (b.scheme, b.netloc):
        sys.exit(f"svc: {name}: only URLs on {b.scheme}://{b.netloc} are allowed")
    allow = web.get("paths") or []
    if allow and not any(u.path.startswith(p) for p in allow):
        sys.exit(f"svc: {name}: path not allowed (paths: {', '.join(allow)})")
    return url


def web_curl(name, web, url, method="GET", data_lines=(), out=None):
    """curl with auth in a 0600 config file and a per-service cookie jar; returns (code, http_status, final_url, content_type, body)"""
    auth, jar = web.get("auth") or {"type": "none"}, web_paths(name)
    cfg = ['url = ' + api_part._q(url), 'location', 'max-redirs = 10', 'max-time = 30', f'cookie-jar = {api_part._q(jar)}', f'cookie = {api_part._q(jar)}',
           'user-agent = "tentaclai (+svc web)"', 'write-out = "\\n%{http_code} %{url_effective} %{content_type}"']
    t = auth.get("type", "none")
    if t == "basic":
        cfg.append(f'user = {api_part._q(auth["user"] + ":" + auth["password"])}')
    elif t == "bearer":
        cfg.append(f'header = {api_part._q("Authorization: Bearer " + auth["token"])}')
    elif t == "header":
        cfg.append(f'header = {api_part._q(auth["header"] + ": " + auth["value"])}')
    for h, v in (web.get("headers") or {}).items():
        cfg.append(f'header = {api_part._q(h + ": " + v)}')
    if method == "POST":
        cfg.append('request = "POST"')
        cfg += [f'data-urlencode = {api_part._q(l)}' for l in data_lines]
    if web.get("insecure_tls"):
        cfg.append("insecure")
    code, stdout, stderr = api_part._curl_secret(name, [], cfg)
    body, _, meta = stdout.rpartition("\n")
    parts = meta.split(" ", 2) + ["", "", ""]
    return code, parts[0], parts[1], parts[2], (body if code == 0 else stderr.strip())


def web_login(name, web):
    a = web["auth"]
    login = web_url(name, web, a.get("login_url", "/login"))
    fields = dict(a.get("fields") or {})
    if a.get("csrf_field"):  # fetch the login form first and copy its hidden token
        code, st, final, ctype, body = web_curl(name, web, login)
        m = re.search(r'name=["\']' + re.escape(a["csrf_field"]) + r'["\'][^>]*value=["\']([^"\']*)', body) or \
            re.search(r'value=["\']([^"\']*)["\'][^>]*name=["\']' + re.escape(a["csrf_field"]), body)
        if m:
            fields[a["csrf_field"]] = m.group(1)
    code, st, final, ctype, body = web_curl(name, web, login, "POST", [f"{k}={v}" for k, v in fields.items()])
    return code == 0 and st[:1] in ("2", "3")


def web_fetch(name, web, path):
    url = web_url(name, web, path)
    form = (web.get("auth") or {}).get("type") == "form"
    jar = web_paths(name)
    if form and (not os.path.exists(jar) or os.path.getsize(jar) == 0):
        web_login(name, web)
    res = web_curl(name, web, url)
    if form:
        login_path = web_url(name, web, web["auth"].get("login_url", "/login")).split("?")[0]
        if res[1] in ("401", "403") or res[2].split("?")[0] == login_path:
            web_login(name, web)
            res = web_curl(name, web, url)
    return res


def cmd_web(services, args):
    webs = core.part_services(services, "web")
    if not args:
        if not webs:
            print("No web sources.")
            return 0
        print(f"{'Name':<16}{'Auth':<9}{'URL':<44}Status")
        for n, s in webs.items():
            w = core.render(s["web"])
            print(f"{n:<16}{(w.get('auth') or {}).get('type', 'none'):<9}{w.get('base_url', ''):<44}{core.status(s)}")
        return 0
    name, rest = args[0], args[1:]
    web = gate.get_part(services, name, "web")
    mode = "text"
    while rest and rest[0] in ("--raw", "--links", "--login"):
        mode, rest = rest[0][2:], rest[1:]
    if mode == "login":
        ok = web_login(name, web)
        print(f"{name}: login {'ok' if ok else 'failed'}")
        return 0 if ok else 1
    path = rest[0] if rest else "/"
    code, st, final, ctype, body = web_fetch(name, web, path)
    if code != 0:
        sys.exit(f"svc: {name}: {body[:200]}")
    if mode == "raw" or "html" not in ctype:
        sys.stdout.write(body)
        safeguards.guard("web page", name, "web", f"fetch {path}", body)
        return 0 if st.startswith("2") else 1
    p = _HTMLText(final)
    p.feed(body)
    if mode == "links":
        base = web["base_url"].split("/")[2]
        for l in dict.fromkeys(l for l in p.links if l.split("/")[2:3] == [base]):
            print(l)
        return 0
    limit = int(web.get("max_chars", 40000))
    text = p.text()
    print(f"# {tclib.clean_untrusted(p.title.strip())[0] or final}\n<{final}>  HTTP {st}"
          + (f" – {p.hidden} hidden element(s) left out" if p.hidden else "") + "\n")
    print(safeguards.framed(text, safeguards.WEB_START, safeguards.WEB_END, limit))
    safeguards.guard("web page", name, "web", f"fetch {path}", text + "\n" + " ".join(p.hidden_text))
    return 0 if st.startswith("2") else 1


def web_test(name, web):
    code, st, final, ctype, body = web_fetch(name, web, web.get("test_path", "/"))
    if code != 0:
        return False, body[:180]
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    form = (web.get("auth") or {}).get("type") == "form"
    login_hit = form and final.split("?")[0].endswith(web["auth"].get("login_url", "/login").split("?")[0])
    ok = st.startswith("2") and not login_hit
    return ok, f"{final} → HTTP {st}" + (f" „{title.group(1).strip()[:60]}“" if title else "") + (" (still on the login page)" if login_hit else "")
