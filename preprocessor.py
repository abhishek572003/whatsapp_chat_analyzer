import pandas as pd
import re

def preprocess(data):
    # Updated date pattern for Android's 12-hour format with 2-digit year
    date_pattern = r'\d{1,2}/\d{1,2}/\d{2},\s\d{1,2}:\d{2}\s[APap][mM]\s-\s'
    
    dates = re.findall(date_pattern, data)
    messages = re.split(date_pattern, data)[1:]
    
    df = pd.DataFrame({'user_message': messages, 'message_date': dates})
    
    # Convert message_date to datetime with correct format
    df['message_date'] = pd.to_datetime(
        df['message_date'], 
        format='%d/%m/%y, %I:%M %p - ',  # Updated format specifiers
        errors='coerce'
    )
    
    # Drop any rows with NaT in message_date
    df = df.dropna(subset=['message_date'])
    
    # Rename and extract components
    df.rename(columns={'message_date': 'date'}, inplace=True)
    users = []
    messages = []
    
    for message in df['user_message']:
        entry = re.split('([\w\W]+?):\s', message)
        if entry[1:]:
            users.append(entry[1])
            messages.append(entry[2])
        else:
            users.append('group_notification')
            messages.append(entry[0])
    
    df['user'] = users
    df['message'] = messages
    df.drop(columns=['user_message'], inplace=True)

    # In preprocessor.py (add to preprocessing pipeline)
    df['sensitive_data'] = df['message'].apply(
    lambda x: len(re.findall(r'\b(?:\d[ -]*?){13,16}\b', x))  # Credit cards
    )
    
    # Extract additional datetime components
    df['only_date'] = df['date'].dt.date
    df['year'] = df['date'].dt.year
    df['month_num'] = df['date'].dt.month
    df['month'] = df['date'].dt.month_name()
    df['day'] = df['date'].dt.day
    df['day_name'] = df['date'].dt.day_name()
    df['hour'] = df['date'].dt.hour
    df['minute'] = df['date'].dt.minute
    
    # Create period for heatmap
    df['period'] = df['hour'].apply(lambda x: 
        str(x) + "-" + str(x+1) if x != 23 else '23-0'
    )
    
    return df