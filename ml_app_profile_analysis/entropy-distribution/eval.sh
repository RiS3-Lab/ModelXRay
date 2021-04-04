#scripts used for extract entropy range
ag ".tflite" ../reports/us.entropy_report.filtered | head | cut -d' ' -f1|cut -d':' -f2
ag ".pb" ../reports/us.entropy_report.filtered | head | cut -d' ' -f1|cut -d':' -f2
ag ".prototxt" ../reports/us.entropy_report.filtered | head -n 11| cut -d' ' -f1|cut -d':' -f2
ag ".prototxt" ../reports/360.entropy_report.filtered | head -n 11| cut -d' ' -f1|cut -d':' -f2
ag ".model" ../reports/us.entropy_report.filtered | head | cut -d' ' -f1|cut -d':' -f2
