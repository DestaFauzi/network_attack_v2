
import pandas as pd
import os

# Create a dummy dataframe
data = {
    'packet_id': [1, 2, 3],
    'timestamp': ['2023-01-01 12:00:00.000', '2023-01-01 12:00:01.000', '2023-01-01 12:00:02.000'],
    'src_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.3'],
    'flags': ['S', 'PA', 'F']
}
df = pd.DataFrame(data)

# Define output path
output_path = 'test_export.xlsx'

try:
    # Save to Excel
    print("Attempting to save to Excel...")
    df.to_excel(output_path, index=False, engine='openpyxl')
    print(f"Successfully saved to {output_path}")
    
    # Verify we can read it back
    print("Attempting to read back...")
    df_read = pd.read_excel(output_path)
    print("Successfully read back.")
    print(df_read)
    
except Exception as e:
    print(f"Error: {e}")
