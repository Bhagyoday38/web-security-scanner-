import unittest

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

    def test_missing_url_is_not_rendered_by_missing_template(self):
        client = app.app.test_client()
        response = client.post('/scan_url', data={'url': ''})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'URL is required', response.data)


if __name__ == '__main__':
    unittest.main()
