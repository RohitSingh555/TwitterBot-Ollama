import json

def parse_cron_responses(cron_responses):
    # Remove triple quotes if present
    cron_responses = cron_responses.strip('"""')

    # Replace single quotes with double quotes
    cron_responses = cron_responses.replace("'", '"')

    # Convert to JSON object
    json_data = json.loads(cron_responses)

    return json_data


# @app.route('/db_tweets_on_timeline', methods=['GET'])
# async def database_tweets_with_responses_on_timeline():
#     # Get tweets
#     user_id = session.get('user_id')
#     latest_response_time = get_latest_gpt_response_time(user_id)
#     tweets_with_responses = []
    
#     if latest_response_time and (datetime.now() - latest_response_time) < timedelta(hours=1):
#         tweets = GPTResponses.query.filter_by(user_id=user_id).order_by(desc(GPTResponses.created)).limit(20).all()
#         print("tweets from db --> ")
#         print(tweets)
#         for tweet in tweets:
#             gpt_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet.responded_to_tweet_id).first()
#             print('GPT response ', gpt_response)
#             if gpt_response:
#                 response_for_tweet = gpt_response.response_tweet
#                 tweets_with_responses.append({"tweet": tweet, "response": response_for_tweet})
#     else:
#         tweets = get_tweets_on_timeline(user_id)
#         for tweet in tweets:
#             gpt_response = GPTResponses.query.filter_by(responded_to_tweet_id=tweet['id']).first()
#             if gpt_response:
#                 tweets_with_responses.append({"tweet": tweet, "response": gpt_response.response_tweet})
#             else:
#                 # TODO: call assistant to generate response + save to db + appebd
#                 assistant = Assistant.query.filter_by(user_id=user_id).first()
#                 if not assistant:
#                     return jsonify({'error': 'Assistant not found for the user'}), 404
                
#                 response =  await get_agent_response(assistant.assistant_id, tweet['text'])
#                 response_for_tweet = response[0]
#                 try:
#                     preview_image_url=tweet['preview_image_url']
#                 except:
#                     preview_image_url=None
#                 gpt_response = GPTResponses(response_tweet=response_for_tweet, responded_to_tweet_id=tweet['id'], responded_to_tweet=tweet['text'],responded_to_tweet_image_url=preview_image_url,twitter_usernames=tweet['username'],author_id=tweet['author_id'])
#                 db.session.add(gpt_response)
                
#                 tweets_with_responses.append({"tweet": tweet, "response": response_for_tweet})
        
#     # tweets = GPTResponses.query.filter_by(user_id=user_id).order_by(GPTResponses.created.desc()).limit(5).all()
    
#     db.session.commit()        
#     return tweets_with_responses
