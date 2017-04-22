#!/usr/bin/python3
from google.cloud import pubsub
import logging

def receive_message(topic_name, subscription_name):
    """Receives a message from a pull subscription."""
    pubsub_client = pubsub.Client()
    topic = pubsub_client.topic(topic_name)
    subscription = topic.subscription(subscription_name)

    # Change return_immediately=False to block until messages are received.
    results = subscription.pull(return_immediately=True)

    for ack_id, message in results:
        logging.info('Message Received: {}: {}, {}\n'.format(message.message_id, message.data, message.attributes))

    # Acknowledge received messages. If you do not acknowledge, Pub/Sub will redeliver the message.
    if results:
        subscription.acknowledge([ack_id for ack_id, message in results])
    return results