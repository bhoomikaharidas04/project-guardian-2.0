import pandas as pd
import re
import json

# --- PII Pattern Definitions ---
PII_PATTERNS = {
    'phone': re.compile(r'^\d{10}$'),
    'aadhar': re.compile(r'^\d{4}\s?\d{4}\s?\d{4}$'),
    'passport': re.compile(r'^[A-Z]?\d{7}$'),
    'upi_id': re.compile(r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$|^(\d{10})@[a-zA-Z]{2,64}$')
}

COMBINATORIAL_PII_KEYS = {'name', 'email', 'address', 'device_id', 'ip_address'}

# --- Redaction Functions ---
def redact_phone(phone_num):
    if phone_num and len(phone_num) == 10:
        return f'{phone_num[:2]}XXXXXX{phone_num[-2:]}'
    return phone_num

def redact_string(value):
    return '[REDACTED_PII]'

def redact_combinatorial(key, value):
    if key == 'name':
        parts = value.split()
        if len(parts) > 1:
            first = parts[0]
            last = parts[-1]
            return f'{first[0]}XXX {last[0]}XXXX'
        else:
            return f'{value[0]}XXX'
    elif key == 'email':
        parts = value.split('@')
        if len(parts) == 2:
            return f'XX{parts[0][2:-2]}XX@{parts[1]}'
        return 'XX[REDACTED_EMAIL]'
    elif key == 'address':
        return '[REDACTED_ADDRESS]'
    elif key in ['device_id', 'ip_address']:
        return '[REDACTED]'
    return value

# --- Main Detection & Redaction Logic ---
def process_data(data):
    is_pii = False
    new_data = data.copy()

    # Check for Standalone PII
    for key, pattern in PII_PATTERNS.items():
        if key in new_data and isinstance(new_data[key], str) and pattern.match(new_data[key]):
            is_pii = True
            if key == 'phone':
                new_data[key] = redact_phone(new_data[key])
            else:
                new_data[key] = redact_string(new_data[key])

    # Check for Combinatorial PII
    combinatorial_keys_found = [key for key in COMBINATORIAL_PII_KEYS if key in new_data]
    combinatorial_count = len(combinatorial_keys_found)
    
    if combinatorial_count >= 2:
        is_pii = True
        for key in combinatorial_keys_found:
            new_data[key] = redact_combinatorial(key, new_data[key])
    
    return json.dumps(new_data), is_pii

# --- Main Program Execution ---
def main(input_csv_path, output_csv_path):
    try:
        df = pd.read_csv(input_csv_path)
        print(f"Columns found in CSV: {list(df.columns)}")
    except FileNotFoundError:
        print(f"Error: File '{input_csv_path}' not found.")
        return
    
    output_records = []
    
    # Check if required columns exist
    if 'record_id' not in df.columns:
        print("Error: 'record_id' column not found in CSV.")
        return
    
    # Try to find the data column (case insensitive)
    data_columns = [col for col in df.columns if 'data' in col.lower() or 'json' in col.lower()]
    
    if not data_columns:
        print("Error: No data column found. Expected a column containing 'data' or 'json' in its name.")
        return
    
    data_column = data_columns[0]  # Use the first matching column
    print(f"Using data column: '{data_column}'")
    
    for index, row in df.iterrows():
        record_id = row['record_id']
        try:
            data = json.loads(row[data_column])
            redacted_data, is_pii = process_data(data)
            output_records.append([record_id, redacted_data, is_pii])
        except json.JSONDecodeError:
            print(f"Skipping record_id {record_id} due to invalid JSON.")
            output_records.append([record_id, row[data_column], False])
        except Exception as e:
            print(f"Error processing record_id {record_id}: {e}")
            output_records.append([record_id, row[data_column], False])

    output_df = pd.DataFrame(output_records, columns=['record_id', 'redacted_data_json', 'is_pii'])
    output_df.to_csv(output_csv_path, index=False)
    print(f"Processing complete. Output saved to {output_csv_path}")

if __name__ == "__main__":
    input_file = 'iscp_pii_dataset_-_Sheet1.csv'
    output_file = 'redacted_output_Bhoomika_Haridas.csv'
    main(input_file, output_file)