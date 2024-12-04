from website_analyzer.analyzer import WebsiteAnalyzer

def main():
    # Initialize the analyzer with the target website
    analyzer = WebsiteAnalyzer("albashmoparmeg.com")
    
    # Run the analysis
    analyzer.analyze()

if __name__ == "__main__":
    main()
