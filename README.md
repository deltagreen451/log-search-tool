# log-search-tool
BASH script to search server logs for school assignment

A server access log tool to:
1. Run a search on available server access logs based on any single criteria the user chooses, i.e. PROTOCOL, SRC IP, SRC PORT, DEST IP, DEST PORT, PACKETS or BYTES.
2. The search is to be applied to one (1) specific log file that the user will choose from an on-screen list the script will provide.
3. The result of each search conducted by the user are to be exported to a file named as follows – search_results_logfilename_currentdatetime.csv, where logfilename is the name of the log file searched (minus the .csv extension) and currentdatetime is a timestamp generated by the system.
4. Search results are only to include those matching rows in the log file that are marked as suspicious. Those marked as normal are to be excluded from the results.
5. When the PACKETS or BYTES fields are used as search criteria, totals for each of these should also be calculated and displayed as the final row of the search results printed to the screen

