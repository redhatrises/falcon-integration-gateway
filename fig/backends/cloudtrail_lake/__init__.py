# import traceback
# import boto3
# from botocore.exceptions import ClientError
# import json
from ...config import config
from ...log import log


class Submitter():
    def __init__(self, event):
        self.event = event
        self.ingestion_channel_id = config.get('cloudtrail_lake', 'ingestion_channel_id')
        self.role_arn = config.get('cloudtrail_lake', 'role_arn')
        self.account_id = config.get('cloudtrail_lake', 'account_id')

    # Map event into Open Audit Event format
    def open_audit_event(self):
        uid = self.event.original_event.uid
        event = self.event.original_event['event']
        metadata = self.event.original_event['metadata']
        event_time = self.event.time.isoformat(timespec='seconds') + 'Z'

        user_identity = {
            "type": metadata['eventType'],
            "principleId": event['UserId'],
            "details": {"AuditKeyValues": "empty"}
        }

        # Not all events have AuditKeyValues
        if self.event.audit_key_values:
            user_identity['details']['AuditKeyValues'] = event['AuditKeyValues']

        event_data = {
            "version": metadata['version'],
            "userIdentity": user_identity,
            "userAgent": "falcon-integration-gateway",
            "eventSource": "CrowdStrike",
            "eventName": event['OperationName'],
            "eventTime": event_time,
            "UID": uid,
            "sourceIPAddress": event['UserIp'],
            "recipientAccountId": self.account_id,
            "additionalEventData": {
                "raw": self.event.original_event
            }
        }

        return event_data

    def submit(self):
        log.info("Posting event to cloudtrail lake.")
        # print(json.dumps(self.open_audit_event(), indent=4))
        print(self.open_audit_event())


class Runtime():
    RELEVANT_EVENT_TYPES = ['AuthActivityAuditEvent']

    def __init__(self):
        log.info("AWS CloudTrail Lake Backend is enabled.")

    # def is_relevant(self, falcon_event):
    #     if falcon_event.service_name.lower() == "crowdstrike authentication":
    #         log.info(vars(falcon_event))
    #         print()
    #         return True
    #     return False

    def is_relevant(self, falcon_event):
        return falcon_event.service_name.lower() == "crowdstrike authentication"

    def process(self, falcon_event):
        Submitter(falcon_event).submit()


__all__ = ['Runtime']
