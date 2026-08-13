import sys
import time
from src.docx_processor import DocxProcessor

def main():
    input_file = "Red Herring Prospectus.docx"
    output_file = "Red_Herring_Prospectus_REDACTED.docx"

    print(f"Starting PII redaction on '{input_file}'...")
    start_time = time.time()

    processor = DocxProcessor()
    stats = processor.process_document(input_file, output_file)

    elapsed = time.time() - start_time
    print(f"Redaction completed in {elapsed:.2f} seconds.")
    print(f"Total entities detected & redacted: {stats['total_entities_detected']}")
    print("Breakdown by entity type:")
    for pii_type, count in stats["entities_by_type"].items():
        print(f"  - {pii_type}: {count}")

    print(f"Paragraphs processed: {stats['paragraphs_processed']}")
    print(f"Tables processed: {stats['tables_processed']}")
    print(f"Headers/Footers processed: {stats['headers_footers_processed']}")
    print(f"Output saved to: {output_file}")

if __name__ == "__main__":
    main()
