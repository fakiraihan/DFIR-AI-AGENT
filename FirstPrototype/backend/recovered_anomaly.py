start_idx = content.find(start_marker)\
            if start_idx != -1:\
                start_idx = content.find(\'\\\
\', start_idx) + 1\
                end_marker = \'