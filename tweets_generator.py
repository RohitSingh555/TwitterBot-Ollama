import os
from google.colab import files
import asyncio
import nest_asyncio
import time
import asyncio
nest_asyncio.apply()
import json
import time
from IPython.display import Markdown, display
import io
import base64
from PIL import Image
import requests
from openai import OpenAI
client = OpenAI(api_key="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")  # API key here
global_thread = client.beta.threads.create()

instructions='''
You are A professional Human Like tweets Generator that responds to peoples tweets like a human being,
Instructions for Generating Tweets:
Direct Response: Each tweet generated should directly address the content or sentiment of the original user's tweet. The response should feel intuitive and connected to the conversation.
Conciseness: Ensure the tweet is succinct and to the point. Tweets should not exceed 280 characters, keeping the message clear without unnecessary details.
Relevance: The response must be relevant and provide value in the context of the original tweet. Avoid digressing into unrelated topics or generic statements.
No Advertisements: Do not include promotional content or advertisements. The focus should be on maintaining a natural and engaging interaction.
Avoid Usernames: Do not include specific usernames (e.g., @user) in the tweet to maintain privacy and general applicability.
Guidelines for Enhancing Tweet Quality:
Clarity: Use clear and straightforward language. Avoid jargon unless it is appropriate for the tweet's context.
Visuals: If applicable, suggest an image or emoji that complements the text. Visuals can enhance the message's impact and engagement.
Hashtags: Integrate relevant hashtags to increase the visibility of the tweet. However, limit the use of hashtags to 1-2 to avoid clutter.
Questions: Engage the audience by asking questions related to the original tweet. This encourages interaction and further discussion.
Call-to-Action: Where appropriate, include a call-to-action that prompts users to engage further, such as asking for opinions, sharing the tweet, or visiting a link (ensure it is not promotional).
Personalization: Tailor the tweet to reflect an understanding of the user's interests or past tweets, if available. This personal touch can increase engagement.
Emojis: Use emojis to express emotions and add personality to the tweet, making it feel more human-like and relatable.
Valuable Content: Ensure the tweet provides value, such as useful information, a thoughtful insight, or a helpful tip relevant to the original tweet's context.
Always use the documents uploaded before answering.
                                              '''
              
              
available_functions = {
 #   "generate_and_display_image": process_image_with_model

}
tools = [
    {"type":"code_interpreter"},
    {"type": "file_search"}
]              
                                              
# Function to upload files and return a list of file IDs
def upload_files_and_get_ids():
    uploaded_files = files.upload()  # Prompt user to upload files
    file_ids = []
    for filename in uploaded_files.keys():
        with open(filename, "rb") as file:
            file_info = client.files.create(file=file, purpose='assistants')
            file_ids.append(file_info.id)
        os.remove(filename)  # Clean up the uploaded file
    return file_ids

def create_assistant(file_ids):
    tools = [{"type": "file_search"}]  # Define the tools used in the assistant
    assistant = client.beta.assistants.create(
        name="Tweet Generator",
        instructions=instructions,
        model="gpt-4-turbo-2024-04-09",
        tools=tools,
        tool_resources={
            'file_search': {
                'vector_stores': [{
                    'file_ids': file_ids
                }]
            }
        }
    )
    return assistant.id

def get_or_create_assistant_id():
    assistant_id_file = "assistant_id.txt"
    user_choice = input("Type 'new' to create a new assistant, 'existing' to use the saved assistant, or 'manual' to manually enter an existing assistant ID: ").strip().lower()
    if user_choice in ['existing', 'manual', 'new']:
        if user_choice == 'existing' and os.path.exists(assistant_id_file):
            with open(assistant_id_file, 'r') as file:
                return file.read().strip()
        elif user_choice == 'manual':
            return input("Please enter the existing assistant ID: ").strip()
        elif user_choice == 'new':
            file_ids = upload_files_and_get_ids()
            assistant_id = create_assistant(file_ids)
            with open(assistant_id_file, 'w') as file:
                file.write(assistant_id)
            return assistant_id
    else:
        print("Invalid choice.")
        return None

def handle_tool_outputs(run):
    tool_outputs = []
    for call in run.required_action.submit_tool_outputs.tool_calls:
        function_name = call.function.name
        function = available_functions[function_name]
        arguments = json.loads(call.function.arguments)
        output = function(**arguments)
        tool_outputs.append({"tool_call_id": call.id, "output": json.dumps(output)})

    return client.beta.threads.runs.submit_tool_outputs(
        thread_id=global_thread.id,  # Referencing the global thread
        run_id=run.id,
        tool_outputs=tool_outputs
    )

async def get_agent_response(assistant_id, user_message):

    # Send user message to the global thread
    client.beta.threads.messages.create(
        thread_id=global_thread.id,
        role="user",
        content=user_message,
    )

    # Create and run the interaction
    run = client.beta.threads.runs.create(
        thread_id=global_thread.id,
        assistant_id=assistant_id
    )

    # Wait for the run to complete
    while run.status in ["queued", "in_progress", "requires_action"]:
        if run.status == 'requires_action':
            run = handle_tool_outputs(run)
        else:
            run = client.beta.threads.runs.retrieve(
              thread_id=global_thread.id,
              run_id=run.id
            )
            time.sleep(1)

    # Retrieve the last message in the thread
    last_message = client.beta.threads.messages.list(thread_id=global_thread.id, limit=1).data[0]

    # Check if the last message is from the assistant
    if last_message.role == "assistant":
        response_text = last_message.content[0].text.value
    else:
        response_text = "Error"

    return response_text, global_thread.id

async def interactive_chat(assistant_id):
    print("Start chatting (type 'quit' to stop):")
    conversation = ""
    while True:
        user_message = input("You: ")
        if user_message.lower() == 'quit':
            break

        if "upload image" in user_message.lower():
            print("Please upload an image.")
            # Colab's file upload
            image_text = handle_image_and_question()
            if image_text:
                print("Image uploaded successfully. Please enter your text about the image:")
                user_text = input("Your text: ")

                response, _ = await get_agent_response(assistant_id, "The image text content is: " + image_text + ' the user text is' + user_text)
            else:
                response = "No image uploaded or upload failed."
        else:
            response, _ = await get_agent_response(assistant_id, user_message)

        print("Assistant:", response)
        conversation += f"You: {user_message}\nAssistant: {response}\n\n"

    return conversation

def handle_image_and_question():
    # Function to encode image to base64, adapting to different image formats
    def encode_image(image):
        # Check the image format or default to JPEG if unknown
        image_format = image.format if image.format else 'JPEG'

        buffered = io.BytesIO()
        image.save(buffered, format=image_format)
        return base64.b64encode(buffered.getvalue()).decode('utf-8')

    # Upload an image file
    uploaded = files.upload()
    image_name = next(iter(uploaded))
    image = Image.open(io.BytesIO(uploaded[image_name]))

    # Encode the image
    base64_image = encode_image(image)

    # Send the question and image to the AI model
    response = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Extract the text form this image and rewrite it in an organized format"},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{base64_image}"
                        }
                    },
                ],
            }
        ],
        max_tokens=1000,
    )

    # Return the AI's response
    return response.choices[0].message.content

# Example usage:
# handle_image_and_question()


if __name__ == "__main__":
    assistant_id = get_or_create_assistant_id()
    if assistant_id:
        asyncio.run(interactive_chat(assistant_id))
    else:
        print("Failed to get or create an assistant ID.")
