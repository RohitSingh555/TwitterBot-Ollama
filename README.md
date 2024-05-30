# Tweet AI Responder

This application allows you to interact with your tweets and get AI-generated replies. The application also includes a cron job functionality to automate the process of fetching and responding to tweets.

## Prerequisites

Ensure you have Python and pip installed on your computer.

## Setup Instructions

1. **Create a Virtual Environment**

   Open your terminal and navigate to your project directory. Run the following commands to create and activate a virtual environment:

```
pip install virtualenv
virtualenv env
source env/bin/activate # On Windows use env\Scripts\activate
```

2. **Install Dependencies**

Install the required dependencies by running:

`pip install -r requirements.txt`

3. **Run the Application**

Start the application with the following command:

`python main.py`

4. **Create an Assistant**

You can create an assistant using either a file or a checkbox:

- Go to `/`
- Follow the prompts to create an assistant

5. **View Tweets and AI Replies**

After creating an assistant, navigate to the home page (`/`). You will see your tweets and the AI-generated replies there.

## Running the Cron Job

To automate the fetching and responding to tweets, follow these steps:

1. **Create an Assistant**

Follow the instructions above to create an assistant.

2. **Enable Automation**

- Go to the dashboard.
- Toggle the 'Automate' button to enable automation.

3. **Run the Cron Job Script**

Copy and save the following script as `cron_job.sh`:

`#!/bin/bash

API_URL="http://127.0.0.1:3000/cron-job"

while true; do

  response=$(curl -s -w "%{http_code}" -o /dev/null "$API_URL")

  sleep 900
done
#!/bin/bash
`

**Then, run the script using Git Bash (if you are on Windows):**

./script_name.sh


This will start the cron job that makes API calls every minute to fetch and respond to tweets automatically.

## Additional Information

- Make sure the server is running when you execute the cron job script.
- The cron job script will continuously run in the background and make API calls every 600 seconds - 10 min .