import csv
from collections import defaultdict

csv_file = 'mac_system_logs.csv'

thermal_summary = {
    "source": "THERMAL",
    "total_events": 0,
    "high_pressure_events": [],
    "low_pressure_events": []
}

with open(csv_file, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        timestamp = f"{row['Month']} {row['Date']} {row['Time']}"
        component = row['Component']
        message = row['Content']

        # thermal events only
        if "Thermal pressure state" in message:
            thermal_summary["total_events"] += 1

            # high or low pressure
            if "Thermal pressure state: 1" in message: # flag because possible warning
                thermal_summary["high_pressure_events"].append({
                    "timestamp": timestamp,
                    "component": component,
                    "message": message
                })
            else:
                thermal_summary["low_pressure_events"].append({
                    "timestamp": timestamp,
                    "component": component,
                    "message": message
                })

# print
print("THERMAL LOG SUMMARY")
print(f"Total thermal events: {thermal_summary['total_events']}")
print(f"High pressure events: {len(thermal_summary['high_pressure_events'])}")
print(f"Low pressure events: {len(thermal_summary['low_pressure_events'])}")
print("Sample high-pressure events:")
for event in thermal_summary['high_pressure_events'][:3]:  # show all high pressure, change to maybe first 3
    print(event)
