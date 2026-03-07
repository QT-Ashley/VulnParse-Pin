#!/usr/bin/env python3
"""
VulnParse-Pin Performance Profiling Harness

Usage:
    python profile_runner.py --file <input_file> [options]

Features:
    - cProfile-based CPU profiling
    - Customizable output formats (stats, snakeviz-ready)
    - Memory profiling integration (optional)
    - Automated report generation

Examples:
    # Profile 700k stress test with ERROR logging
    python profile_runner.py --file tests/regression_testing/nessus_xml/nessus_stress_700k.xml \\
        --mode offline --allow-large --log-level ERROR --output profile_700k.stats

    # Profile with detailed report
    python profile_runner.py --file tests/regression_testing/nessus_xml/real_nessus.nessus \\
        --mode offline --report --top 50

"""

import cProfile
import pstats
import io
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional

def run_profiled_vulnparse(args: argparse.Namespace) -> tuple[Optional[pstats.Stats], float]:
    """
    Run VulnParse-Pin with cProfile instrumentation.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Tuple of (pstats.Stats object, runtime_seconds)
    """
    print("=" * 80)
    print("VulnParse-Pin Performance Profiling Harness")
    print("=" * 80)
    print(f"Target: {args.file}")
    print(f"Mode: {args.mode}")
    print(f"Log Level: {args.log_level}")
    print(f"Output: {args.output or 'memory (no stats file)'}")
    print("=" * 80)
    print()
    
    # Build vulnparse-pin command args
    vpp_args = [
        '--file', args.file,
        '--mode', args.mode,
        '--log-level', args.log_level,
    ]
    
    if args.allow_large:
        vpp_args.append('--allow-large')
    
    if args.output_json:
        vpp_args.extend(['--output', args.output_json])
    
    # Monkeypatch sys.argv for vulnparse_pin's arg parser
    original_argv = sys.argv
    sys.argv = ['vulnparse_pin'] + vpp_args
    
    try:
        # Import vulnparse_pin main after argv setup
        from vulnparse_pin.main import main as vpp_main
        
        # Create profiler
        profiler = cProfile.Profile()
        
        # Run with profiling
        print("[Profiler] Starting instrumented run...")
        start_time = datetime.now()
        
        profiler.enable()
        try:
            vpp_main()
        except SystemExit:
            pass  # VulnParse-Pin may call sys.exit()
        finally:
            profiler.disable()
        
        end_time = datetime.now()
        runtime = (end_time - start_time).total_seconds()
        
        print()
        print("=" * 80)
        print(f"[Profiler] Run complete: {runtime:.2f}s")
        print("=" * 80)
        
        # Generate stats
        stats = pstats.Stats(profiler)
        
        # Save to file if requested
        if args.output:
            profiler.dump_stats(args.output)
            print(f"[Profiler] Stats saved to: {args.output}")
        
        return stats, runtime
        
    finally:
        # Restore original argv
        sys.argv = original_argv


def generate_report(stats: pstats.Stats, runtime: float, args: argparse.Namespace) -> str:
    """
    Generate human-readable profiling report.
    
    Args:
        stats: pstats.Stats object from profiling run
        runtime: Total runtime in seconds
        args: Command-line arguments
        
    Returns:
        Formatted report string
    """
    output = io.StringIO()
    
    output.write("=" * 80 + "\\n")
    output.write("VulnParse-Pin Performance Profile Report\\n")
    output.write("=" * 80 + "\\n")
    output.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
    output.write(f"Input: {args.file}\\n")
    output.write(f"Total Runtime: {runtime:.2f}s\\n")
    output.write("=" * 80 + "\\n\\n")
    
    # Sort by cumulative time
    stats.sort_stats(pstats.SortKey.CUMULATIVE)
    
    output.write(f"Top {args.top} Functions by Cumulative Time:\\n")
    output.write("-" * 80 + "\\n")
    
    # Redirect stats output to string buffer
    stats_output = io.StringIO()
    stats.stream = stats_output
    stats.print_stats(args.top)
    output.write(stats_output.getvalue())
    
    output.write("\\n" + "=" * 80 + "\\n")
    output.write(f"Top {args.top} Functions by Total Time (Self):\\n")
    output.write("-" * 80 + "\\n")
    
    stats.sort_stats(pstats.SortKey.TIME)
    stats_output = io.StringIO()
    stats.stream = stats_output
    stats.print_stats(args.top)
    output.write(stats_output.getvalue())
    
    output.write("\\n" + "=" * 80 + "\\n")
    output.write("Analysis:\\n")
    output.write("-" * 80 + "\\n")
    
    # Calculate total function calls
    total_calls = sum(stats.stats[func][0] for func in stats.stats)
    output.write(f"Total Function Calls: {total_calls:,}\\n")
    output.write(f"Average Call Time: {(runtime / total_calls * 1000):.6f}ms\\n")
    output.write("\\n")
    
    # Identify hotspots (functions >5% cumulative time)
    stats.sort_stats(pstats.SortKey.CUMULATIVE)
    output.write("Hotspots (functions >5% cumulative time):\\n")
    hotspot_count = 0
    for func, (cc, nc, tt, ct, callers) in sorted(stats.stats.items(), key=lambda x: x[1][3], reverse=True):
        if ct / runtime > 0.05:
            hotspot_count += 1
            pct = (ct / runtime) * 100
            output.write(f"  {hotspot_count}. {func[2]} ({func[0]}:{func[1]}) - {ct:.2f}s ({pct:.1f}%)\\n")
        else:
            break
    
    if hotspot_count == 0:
        output.write("  No single function exceeds 5% cumulative time (well-distributed execution)\\n")
    
    output.write("\\n" + "=" * 80 + "\\n")
    output.write("Recommendations:\\n")
    output.write("-" * 80 + "\\n")
    if hotspot_count > 5:
        output.write("  • Multiple hotspots detected - consider parallelization or caching\\n")
    elif hotspot_count > 0:
        output.write("  • Focused optimization opportunities - review top hotspot functions\\n")
    else:
        output.write("  • Execution is well-distributed - focus on I/O and algorithmic improvements\\n")
    
    output.write("  • Use snakeviz for visual flame graph: pip install snakeviz && snakeviz <stats_file>\\n")
    output.write("  • Compare against baseline (6m 28s for 700k findings)\\n")
    output.write("=" * 80 + "\\n")
    
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="Profile VulnParse-Pin performance with cProfile",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # VulnParse-Pin arguments
    parser.add_argument('--file', '-f', required=True, help='Input vulnerability scan file')
    parser.add_argument('--mode', default='offline', choices=['online', 'offline'], help='Enrichment mode')
    parser.add_argument('--log-level', default='ERROR', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Logging verbosity')
    parser.add_argument('--allow-large', action='store_true', help='Allow processing >50k findings')
    parser.add_argument('--output-json', help='Output JSON path (optional)')
    
    # Profiling arguments
    parser.add_argument('--output', '-o', help='Output stats file (e.g., profile.stats)')
    parser.add_argument('--report', '-r', action='store_true', help='Generate human-readable report')
    parser.add_argument('--top', type=int, default=50, help='Number of top functions to display (default: 50)')
    parser.add_argument('--report-file', help='Save report to file instead of stdout')
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.file).exists():
        print(f"Error: Input file not found: {args.file}", file=sys.stderr)
        return 1
    
    # Run profiled execution
    try:
        stats, runtime = run_profiled_vulnparse(args)
        
        if stats is None:
            print("[Profiler] Error: No stats generated", file=sys.stderr)
            return 1
        
        # Generate report if requested
        if args.report:
            report = generate_report(stats, runtime, args)
            
            if args.report_file:
                with open(args.report_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"[Profiler] Report saved to: {args.report_file}")
            else:
                print()
                print(report)
        
        print()
        print("[Profiler] Profiling complete!")
        
        if args.output:
            print(f"[Profiler] Analyze with: python -m pstats {args.output}")
            print(f"[Profiler] Visualize with: snakeviz {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"[Profiler] Error during profiling: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
