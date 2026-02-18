# save as a json file

import csv
import json

thermal_events = []

with open('mac_system_logs.csv', newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        timestamp = f"{row['Month']} {row['Date']} {row['Time']}"
        component = row['Component']
        message = row['Content']

        if "Thermal pressure state" in message:
            thermal_events.append({
                'timestamp': timestamp,
                'component': component,
                'message': message
            })

output = {"thermal_events": thermal_events}

with open('thermal_events.json', 'w', encoding='utf-8') as jsonfile:
    json.dump(output, jsonfile, indent=4)

print(f"Saved {len(thermal_events)} thermal events to thermal_events.json")
