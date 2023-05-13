import json
import logging
import azure.functions as func
from json2html import json2html
from PostAzureEventGrid import send_event
from FreshServiceConnection import callfreshserviceapi
import re 
import os
import html



event_grid_domain_endpoint = 'https://evtgd-01-das.canadacentral-1.eventgrid.azure.net/api/events'
event_grid_domain_key = os.environ["EventGridKey"]

def format_conditions(all_of_conditions, alertid):
    html_template = """
        <a style="font-size:14.0pt;font-weight:bold;"
            href="{alert_link}">View the alert in Azure Monitor</a>
        <br>
        <table style="border-collapse: collapse; table-layout: fixed; width: 100%;">
            <tbody>
                {rows}
            </tbody>
        </table>
    """
    row_template = """
        <tr style="border-bottom: 1px solid #DEDEDE;">
            <td style="width:35%;border:none;padding:6.0pt 0in 6.0pt 0in;font-size:12.0pt;color:#11100F;font-family:'Segoe UI Semibold';">{key}</td>
            <td style="width:65%;border:none;padding:6.0pt 0in 6.0pt 0in;font-size:12.0pt;color:#11100F;font-family:'Segoe UI';">{value}</td>
        </tr>
    """

    url_regex = r'(https?://[^\s]+)'

    for condition in all_of_conditions:
        for key, value in condition.items():
            if isinstance(value, str) and re.search(url_regex, value):
                condition[key] = re.sub(url_regex, r'<a href="\1">\1</a>', value)

    rows = ""
    for condition in all_of_conditions:
        for key, value in condition.items():
            row = row_template.format(key=key, value=value)
            rows += row


    alertid = alertid.replace("/", "%2F")
    alert_link = "https://ms.portal.azure.com/#blade/Microsoft_Azure_Monitoring/AlertDetailsTemplateBlade/alertId/" + alertid
    formatted_html_all_of_conditions = html_template.format(alert_link=alert_link, rows=rows)

    return formatted_html_all_of_conditions


def format_message(message):
    event_grid_message = {
        'topic': message['data']['alertContext']['properties']['event_grid_topic'],
        'subject': message['data']['essentials']['alertTargetIDs'][0],
        'id': message['data']['essentials']['alertId'],
        'eventType': message['data']['essentials']['alertRule'],
        'eventTime': message['data']['essentials']['firedDateTime'],
        'data': message['data'],
        "dataVersion": "1",
        "metadataVersion": "1"
    }
    return event_grid_message


def main(msg: func.ServiceBusMessage):
    logging.info('Received message from Service Bus Queue')
    message = json.loads(msg.get_body().decode('utf-8'))
    essentials = message['data']['essentials']
    signal_type = essentials['signalType']
    logging.info(f'Parsing essentials for signal type: {signal_type}')
    
    # Parse the essentials for different signal types
    if signal_type == 'Metric':
        logging.info('Handling metric alert')
        # Handle metric alert
        all_of_conditions = message['data']['alertContext']['condition']['allOf']
        
    elif signal_type == 'Activity Log':
        logging.info('Handling activity log alert')
        # Handle activity log alert
        all_of_conditions = message['data']['alertContext']
        
    elif signal_type == 'Log':
        logging.info('Handling log alert')
        # Handle log alert
        all_of_conditions = message['data']['alertContext']['condition']['allOf']
        
    else:
        logging.warning(f'Unknown signal type: {signal_type}')

    
  
    event_grid_message = format_message(message)
    monitor_conditon = message['data']['essentials']['monitorCondition']
    severity_map = {
    "Sev0": 1,
    "Sev1": 1,
    "Sev2": 2,
    "Sev3": 3,
    "Sev4": 4
    }
    severity = message['data']['essentials']['severity']
    if severity in severity_map:
        mapped_severity = severity_map[severity]
    else:
        mapped_severity = None
    resource = message['data']['essentials']['alertTargetIDs'][-1]
    alertid = message['data']['essentials']['alertId']
    formatted_html_all_of_conditions = format_conditions(all_of_conditions, alertid)
    
    payload ={
        "description": formatted_html_all_of_conditions,
        "subject": message['data']['essentials']['alertRule'] + " on " + resource.split("/")[-1],
        "email": "ncspfreshserviceapi@novachem.com",
        "priority": mapped_severity,
        "status": 2,
        "group_id": int(message['data']['alertContext']['properties']['fs_group_id']),
        "tags":[
            alertid.split('/')[-1]
        ]
    }

    if monitor_conditon == 'Fired':
            if ('alert_testing' in message['data']['alertContext']['properties']) and (message['data']['alertContext']['properties']['alert_testing']):
                logging.info(f'Alert is being tested, only sending fired message to event grid. No ticket will be created')
                send_event(event_grid_domain_endpoint, event_grid_domain_key, event_grid_message)

            else:
                send_event(event_grid_domain_endpoint, event_grid_domain_key, event_grid_message)
                logging.info(f'Creating ticket!')
                createticket = callfreshserviceapi("/api/v2/tickets", "post", payload)
                logging.info(f'fs:{createticket.json}')
    elif monitor_conditon == 'Resolved':
            if ('alert_testing' in message['data']['alertContext']['properties']) and (message['data']['alertContext']['properties']['alert_testing']):
                logging.info(f'Alert is being tested, only sending resolved message to event grid. No ticket will be auto resolved')
                send_event(event_grid_domain_endpoint, event_grid_domain_key, event_grid_message)

            else:
                send_event(event_grid_domain_endpoint, event_grid_domain_key, event_grid_message)
                logging.info(f'Auto resolving ticket!')
                
                alertid = message['data']['essentials']['alertId']
                tag = alertid.split('/')[-1]
                
                query = f'query="tag:\'{tag}\'"'
                ticketid = callfreshserviceapi(f"/api/v2/tickets/filter?{query}", "get")

                data = json.loads(ticketid.content)
                ticketid = data['tickets'][0]['id']

                payload = {
                    "body":"This alert has auto resolved in Azure. The ticket has been closed, no further action is required.",
                    "private": False
                    

                }
                addnote = callfreshserviceapi("/api/v2/tickets/" + str(ticketid) + "/notes", "post", payload)
                
                payload = {
                    "status": 4,
                    "responder_id": 17003082341,
                    "group_id": 17000374736
                }
                apicall = "/api/v2/tickets/" + str(ticketid)
                logging.info(f'apicall: {apicall}')
                closeticket = callfreshserviceapi("/api/v2/tickets/" + str(ticketid), "put", payload)
                logging.info(f'fs:{closeticket.json}')





    else:
         logging.warning(f'Unknown Monitor Condition: {monitor_conditon}')