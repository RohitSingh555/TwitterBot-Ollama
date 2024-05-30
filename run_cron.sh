#!/bin/bash

API_URL="http://127.0.0.1:3000/cron-job"

while true; do

  response=$(curl -s -w "%{http_code}" -o /dev/null "$API_URL")

  sleep 3800
done
#!/bin/bash