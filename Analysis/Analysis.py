import argparse
import init
import utilities as util

# Parse the arguments
parser = argparse.ArgumentParser(description="Automatically analysis of the collectin data")
parser.add_argument("-f", "--full", help = "Execute full analysis", action='store_true')
parser.add_argument("-n", "--network", help = "Perform network analysis", action='store_true')
parser.add_argument("-p", "--process", help = "Perform process analysis", action='store_true')
parser.add_argument("-r", "--registry", help = "Perform registry analysis", action='store_true')
parser.add_argument("-l", "--events-log", help = "Perform Windows events log analysis",  action='store_true')
parser.add_argument("-i", "--interactive", help = "User system with interactive mode",  action='store_true')
parser.add_argument("-k", "--keyword-search", help = "Search certain keyword", dest="keyword")
parser.add_argument("-kl", "--keyword-list", help = "Use keyword list to search", dest="keyword_list")
parser.add_argument("-vt", "--virustotal", help = "Upload to virustotal, 1 for all, 2 for non system program, 3 for non program files nor system", dest="level")

# The movment
args = parser.parse_args()
if args.keyword:
    keyword = args.keyword
elif args.keyword_list:
    keyword = util.keyword_parser(args.keyword_list)
else:
    keyword = None
if args.full:
    init.mainFunc(init.FULL_ANALYSIS, args.level, keyword)
elif args.network:
    init.mainFunc(init.NETWORK_ANALYSIS, args.level, keyword)
elif args.process:
    init.mainFunc(init.PROCESS_ANALYSIS, args.level, keyword)
elif args.registry:
    init.mainFunc(init.REGISTRY_ANALYSIS, args.level, keyword)
elif args.events_log:
    init.mainFunc(init.LOG_ANALYSIS, args.level, keyword)
elif args.interactive:
    init.mainFunc(init.INTERACTIVE, args.level, keyword)
else:
    print(parser.print_help())