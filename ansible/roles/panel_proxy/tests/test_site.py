"""Render the panel vhost template and check its security-relevant lines."""

import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"
VARIABLES = {
    "panel_proxy_marker": "Managed by Ansible role panel_proxy",
    "panel_proxy_listen_address": "127.0.0.1",
    "panel_proxy_bind": "127.0.0.1",
    "panel_proxy_port": 7443,
    "panel_proxy_server_name": "localhost",
    "panel_proxy_upstream": "127.0.0.1:3000",
    "panel_proxy_certificate": "/etc/panel-proxy/tls/server.pem",
    "panel_proxy_certificate_key": "/etc/panel-proxy/tls/server.key",
    "panel_proxy_tls_ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "panel_proxy_client_max_body_size": "16m",
    "panel_proxy_client_type": "browser",
    "panel_proxy_proxy_connect_timeout": "5s",
    "panel_proxy_proxy_send_timeout": "120s",
    "panel_proxy_proxy_read_timeout": "120s",
}


def render(**overrides):
    environment = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=False)
    template = environment.get_template("panel_proxy.conf.j2")
    return template.render(**{**VARIABLES, **overrides})


class SiteTemplateTests(unittest.TestCase):
    def test_listens_only_on_the_loopback_address(self):
        config = render()
        self.assertIn("listen 127.0.0.1:7443 ssl;", config)
        for wildcard in ("listen 443", "listen 80", "0.0.0.0", "listen [::]", "listen :"):
            self.assertNotIn(wildcard, config)

    def test_forwarded_headers_are_overwritten_not_appended(self):
        config = render()
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", config)
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", config)
        self.assertIn("proxy_set_header X-Remnawave-Client-Type browser;", config)
        self.assertNotIn("$proxy_add_x_forwarded_for", config)

    def test_proxies_to_the_panel_upstream_with_websocket_upgrade(self):
        config = render()
        self.assertIn("proxy_pass http://127.0.0.1:3000;", config)
        self.assertIn("proxy_set_header Upgrade $http_upgrade;", config)
        self.assertIn("proxy_http_version 1.1;", config)

    def test_ipv6_loopback_gets_brackets(self):
        config = render(panel_proxy_listen_address="[::1]")
        self.assertIn("listen [::1]:7443 ssl;", config)


if __name__ == "__main__":
    unittest.main()
