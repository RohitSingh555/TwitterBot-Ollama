from main import cron_schedule_tweets  # Import your function from the module where it's defined
from main import User  # Import the User model
import schedule
import time

def should_run():
    users_with_automate_yes = User.query.filter_by(automate='yes').first()
    return users_with_automate_yes is not None

# Schedule the function to run every 1 hour if should_run returns True
schedule.every(1).hours.do(cron_schedule_tweets).when(should_run)

while True:
    schedule.run_pending()
    time.sleep(1)