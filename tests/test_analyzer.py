import unittest
from website_analyzer.analyzer import WebsiteAnalyzer

class TestWebsiteAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = WebsiteAnalyzer("python.org")

    def test_normalize_url(self):
        """Test URL normalization"""
        test_cases = [
            ("example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
            ("https://example.com", "https://example.com"),
        ]
        for input_url, expected_url in test_cases:
            analyzer = WebsiteAnalyzer(input_url)
            self.assertEqual(analyzer.url, expected_url)

    def test_domain_extraction(self):
        """Test domain extraction from URL"""
        test_cases = [
            ("example.com", "example.com"),
            ("http://example.com", "example.com"),
            ("https://example.com/path", "example.com"),
            ("https://sub.example.com", "sub.example.com"),
        ]
        for input_url, expected_domain in test_cases:
            analyzer = WebsiteAnalyzer(input_url)
            self.assertEqual(analyzer.domain, expected_domain)

if __name__ == '__main__':
    unittest.main()
