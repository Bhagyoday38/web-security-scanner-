import unittest
import ipaddress
import socket
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import app


class AppTests(unittest.TestCase):
    def test_trusted_domain_requires_exact_hostname(self):
        self.assertTrue(app.is_trusted_domain('https://github.com'))
        self.assertTrue(app.is_trusted_domain('https://api.github.com'))
        self.assertFalse(app.is_trusted_domain('https://github.com.example.com'))

    def test_normalize_rejects_credentials_and_private_targets(self):
        with self.assertRaises(ValueError):
            app.normalize_scan_url('https://user:password@example.com')
        with self.assertRaises(ValueError):
            app.normalize_scan_url('http://127.0.0.1')

    @patch('app.socket.getaddrinfo')
    def test_normalize_rejects_zero_port(self, getaddrinfo):
        with self.assertRaisesRegex(ValueError, 'valid HTTP or HTTPS URL'):
            app.normalize_scan_url('http://example.com:0')

        getaddrinfo.assert_not_called()

    @patch('app.socket.getaddrinfo')
    def test_public_target_rejects_mixed_public_and_private_dns_answers(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80)),
        ]

        with self.assertRaisesRegex(ValueError, 'Private and local'):
            app._resolve_public_addresses('example.com', 80)

    @patch('app.socket.create_connection')
    @patch('app.ssl.create_default_context')
    @patch('app._resolve_public_addresses')
    def test_https_connection_uses_pinned_ip_and_hostname_for_custom_port(
            self, resolve_addresses, create_context, create_connection):
        raw_socket = Mock()
        tls_socket = Mock()
        resolve_addresses.return_value = [ipaddress.ip_address('93.184.216.34')]
        create_connection.return_value = raw_socket
        create_context.return_value.wrap_socket.return_value = tls_socket
        parsed_url = urlparse('https://example.com:8443/path')

        result = app._open_pinned_connection(parsed_url)

        self.assertIs(result, tls_socket)
        create_connection.assert_called_once_with(('93.184.216.34', 8443), timeout=10)
        create_context.return_value.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname='example.com')

    @patch('app.http.client.HTTPConnection')
    @patch('app._open_pinned_connection')
    def test_fetch_rejects_redirects(self, open_connection, http_connection):
        response = Mock(status=302)
        connection = http_connection.return_value
        connection.getresponse.return_value = response
        connection.sock = Mock()

        with self.assertRaisesRegex(ValueError, 'Redirects are not followed'):
            app._fetch_public_page('https://example.com/')

        connection.request.assert_called_once()
        connection.close.assert_called_once()

    @patch('app.pythonwhois', None)
    @patch('app._fetch_public_page', return_value=(
        '<form action="http://127.0.0.1/submit"><input type="password"></form>', None))
    @patch('app._resolve_public_addresses', return_value=[ipaddress.ip_address('93.184.216.34')])
    def test_scan_passively_flags_insecure_password_form(
            self, resolve_addresses, fetch_page):
        result = app.scan_url('https://example.com')

        self.assertTrue(result['security_checks']['insecure_forms'])
        self.assertEqual(result['result'], 'suspicious')
        fetch_page.assert_called_once()

    def test_scan_ids_do_not_collide_within_the_same_second(self):
        first = app.scan_url('')
        second = app.scan_url('')

        self.assertNotEqual(first['scan_id'], second['scan_id'])

    def test_missing_url_is_not_rendered_by_missing_template(self):
        client = app.app.test_client()
        response = client.post('/scan_url', data={'url': ''})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'URL is required', response.data)


if __name__ == '__main__':
    unittest.main()
