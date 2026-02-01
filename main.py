#!/usr/bin/env python3
"""
Main script - reads text file and extracts data using regex patterns.
Run with: python main.py [optional_file.txt]
"""

import json
import sys
import os
from datetime import datetime
from typing import Dict, Optional

from extractor import extract_all, mask_sensitive_data
from security import SecurityValidator, validate_and_report, create_safe_output


def print_banner():
    """Print application banner."""
    print("=" * 70)
    print("   DATA EXTRACTION & SECURE VALIDATION SYSTEM")
    print("   Regex-Based Text Processing with Security Awareness")
    print("=" * 70)
    print()


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def load_input_file(filepath: str) -> Optional[str]:
    """
    Load text content from a file.
    
    Args:
        filepath: Path to the input file
        
    Returns:
        File contents as string, or None if error
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.")
        return None
    except PermissionError:
        print(f"Error: Permission denied reading '{filepath}'.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None


def format_extracted_data(data: Dict, mask_sensitive: bool = True) -> None:
    """
    Pretty print extracted data to console.
    
    Args:
        data: Dictionary of extracted data
        mask_sensitive: Whether to mask sensitive fields
    """
    print_section("EXTRACTION RESULTS")
    
    # Emails
    print(f"\n📧 EMAIL ADDRESSES ({len(data['emails'])} found):")
    if data['emails']:
        for email in data['emails']:
            display = mask_sensitive_data(email, 'email') if mask_sensitive else email
            print(f"   • {display}")
    else:
        print("   (none found)")
    
    # URLs
    print(f"\n🔗 URLs ({len(data['urls'])} found):")
    if data['urls']:
        for url in data['urls']:
            # Truncate long URLs for display
            display = url if len(url) <= 60 else url[:57] + "..."
            print(f"   • {display}")
    else:
        print("   (none found)")
    
    # Phone Numbers
    print(f"\n📞 PHONE NUMBERS ({len(data['phone_numbers'])} found):")
    if data['phone_numbers']:
        for phone in data['phone_numbers']:
            print(f"   • {phone}")
    else:
        print("   (none found)")
    
    # Credit Cards
    print(f"\n💳 CREDIT CARDS ({len(data['credit_cards'])} found):")
    if data['credit_cards']:
        for card in data['credit_cards']:
            display = mask_sensitive_data(card, 'credit_card') if mask_sensitive else card
            print(f"   • {display}")
    else:
        print("   (none found)")
    
    # Times
    print(f"\n🕐 TIME VALUES ({len(data['times'])} found):")
    if data['times']:
        for i, time in enumerate(data['times']):
            print(f"   • {time}", end="")
            if (i + 1) % 5 == 0:
                print()
            else:
                print("  ", end="")
        print()
    else:
        print("   (none found)")
    
    # HTML Tags
    safe_tags = data['html_tags']['safe']
    dangerous_tags = data['html_tags']['dangerous']
    print(f"\n🏷️  HTML TAGS ({len(safe_tags)} safe, {len(dangerous_tags)} dangerous):")
    if safe_tags:
        print(f"   ✅ Safe tags:")
        for tag in safe_tags[:10]:  # Limit display
            print(f"      • {tag}")
        if len(safe_tags) > 10:
            print(f"      ... and {len(safe_tags) - 10} more")
    if dangerous_tags:
        print(f"   ⚠️  Dangerous tags (BLOCKED):")
        for tag in dangerous_tags:
            print(f"      ❌ {tag}")
    if not safe_tags and not dangerous_tags:
        print("   (none found)")
    
    # Hashtags
    print(f"\n#️⃣  HASHTAGS ({len(data['hashtags'])} found):")
    if data['hashtags']:
        for i, hashtag in enumerate(data['hashtags']):
            print(f"   • {hashtag}", end="")
            if (i + 1) % 4 == 0:
                print()
            else:
                print("  ", end="")
        print()
    else:
        print("   (none found)")
    
    # Currency
    print(f"\n💰 CURRENCY AMOUNTS ({len(data['currency'])} found):")
    if data['currency']:
        for amount in data['currency']:
            print(f"   • {amount}")
    else:
        print("   (none found)")


def format_security_report(report: Dict) -> None:
    """
    Pretty print security report to console.
    
    Args:
        report: Security validation report dictionary
    """
    print_section("SECURITY ANALYSIS")
    
    if report['is_safe']:
        print("\n✅ INPUT SECURITY STATUS: SAFE")
        print("   No significant security threats detected.")
    else:
        print(f"\n⚠️  INPUT SECURITY STATUS: THREATS DETECTED")
        print(f"   Threat Level: {report['threat_level'].upper()}")
        
        print("\n   Issues Found:")
        for issue in report['issues'][:10]:  # Limit display
            print(f"   ❌ [{issue['severity'].upper()}] {issue['type']}: {issue['message']}")
        
        if len(report['issues']) > 10:
            print(f"   ... and {len(report['issues']) - 10} more issues")
        
        if report['recommendations']:
            print("\n   Recommendations:")
            for rec in report['recommendations']:
                print(f"   💡 {rec}")


def save_json_output(data: Dict, security_report: Dict, filepath: str) -> bool:
    """
    Save extraction results and security report to JSON file.
    
    Args:
        data: Extracted data dictionary
        security_report: Security validation report
        filepath: Output file path
        
    Returns:
        True if successful, False otherwise
    """
    output = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'description': 'Data Extraction & Validation Results'
        },
        'security': {
            'is_safe': security_report['is_safe'],
            'threat_level': security_report['threat_level'],
            'issues_count': len(security_report['issues']),
            'recommendations': security_report['recommendations']
        },
        'extracted_data': {
            'emails': {
                'count': len(data['emails']),
                'values': [mask_sensitive_data(e, 'email') for e in data['emails']]
            },
            'urls': {
                'count': len(data['urls']),
                'values': data['urls']
            },
            'phone_numbers': {
                'count': len(data['phone_numbers']),
                'values': data['phone_numbers']
            },
            'credit_cards': {
                'count': len(data['credit_cards']),
                'values': [mask_sensitive_data(c, 'credit_card') for c in data['credit_cards']]
            },
            'times': {
                'count': len(data['times']),
                'values': data['times']
            },
            'html_tags': {
                'safe_count': len(data['html_tags']['safe']),
                'dangerous_count': len(data['html_tags']['dangerous']),
                'safe_tags': data['html_tags']['safe'],
                'dangerous_tags': data['html_tags']['dangerous']
            },
            'hashtags': {
                'count': len(data['hashtags']),
                'values': data['hashtags']
            },
            'currency': {
                'count': len(data['currency']),
                'values': data['currency']
            }
        },
        'summary': {
            'total_items_extracted': (
                len(data['emails']) + 
                len(data['urls']) + 
                len(data['phone_numbers']) +
                len(data['credit_cards']) +
                len(data['times']) +
                len(data['html_tags']['safe']) +
                len(data['hashtags']) +
                len(data['currency'])
            ),
            'dangerous_items_blocked': len(data['html_tags']['dangerous'])
        }
    }
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving JSON output: {e}")
        return False


def main():
    """Main entry point for the data extraction system."""
    print_banner()
    
    # Determine input file
    if len(sys.argv) > 1:
        if sys.argv[1] in ['--help', '-h']:
            print("Usage: python main.py [input_file]")
            print()
            print("Arguments:")
            print("  input_file    Path to text file to process (default: sample_input.txt)")
            print()
            print("Examples:")
            print("  python main.py                    # Use default sample_input.txt")
            print("  python main.py mydata.txt         # Use custom file")
            return
        input_file = sys.argv[1]
    else:
        # Default to sample_input.txt in same directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        input_file = os.path.join(script_dir, 'sample_input.txt')
    
    print(f"📂 Input File: {input_file}")
    
    # Load input
    text = load_input_file(input_file)
    if text is None:
        sys.exit(1)
    
    print(f"📊 Input Size: {len(text):,} characters")
    
    # Step 1: Security Validation
    print("\n🔒 Running security validation...")
    is_safe, security_report = validate_and_report(text)
    
    # Step 2: Extract Data
    print("🔍 Extracting structured data...")
    extracted_data = extract_all(text)
    
    # Step 3: Display Results
    format_extracted_data(extracted_data, mask_sensitive=True)
    format_security_report(security_report)
    
    # Step 4: Save JSON Output
    output_file = os.path.join(os.path.dirname(input_file), 'output.json')
    print(f"\n💾 Saving results to: {output_file}")
    if save_json_output(extracted_data, security_report, output_file):
        print("   ✅ JSON output saved successfully")
    else:
        print("   ❌ Failed to save JSON output")
    
    # Summary
    print_section("SUMMARY")
    total = (
        len(extracted_data['emails']) + 
        len(extracted_data['urls']) + 
        len(extracted_data['phone_numbers']) +
        len(extracted_data['credit_cards']) +
        len(extracted_data['times']) +
        len(extracted_data['html_tags']['safe']) +
        len(extracted_data['hashtags']) +
        len(extracted_data['currency'])
    )
    blocked = len(extracted_data['html_tags']['dangerous'])
    
    print(f"\n   ✅ Total items extracted: {total}")
    print(f"   ❌ Dangerous items blocked: {blocked}")
    print(f"   🔒 Security status: {'SAFE' if is_safe else 'THREATS DETECTED'}")
    print()
    print("=" * 70)
    print("   Processing complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
