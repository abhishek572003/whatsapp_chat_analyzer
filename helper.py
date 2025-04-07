from urlextract import URLExtract
from wordcloud import WordCloud
import pandas as pd
from collections import Counter
import emoji
import requests
import re

extract = URLExtract()

def fetch_stats(selected_user,df):

    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    # fetch the number of messages
    num_messages = df.shape[0]

    # fetch the total number of words
    words = []
    for message in df['message']:
        words.extend(message.split())

    # fetch number of media messages
    num_media_messages = df[df['message'] == '<Media omitted>\n'].shape[0]

    # fetch number of links shared
    links = []
    for message in df['message']:
        links.extend(extract.find_urls(message))

    return num_messages,len(words),num_media_messages,len(links)

def find_sensitive_data(message):
    # Detect credit cards, emails, phone numbers
    credit_card = re.findall(r'\b(?:\d[ -]*?){13,16}\b', message)
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', message)
    phone_numbers = re.findall(r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b', message)
    return len(credit_card) + len(emails) + len(phone_numbers)

def most_busy_users(df):
    x = df['user'].value_counts().head()
    df = round((df['user'].value_counts() / df.shape[0]) * 100, 2).reset_index().rename(
        columns={'index': 'name', 'user': 'percent'})
    return x,df

def create_wordcloud(selected_user,df):

    f = open('stop_hinglish.txt', 'r')
    stop_words = f.read()

    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    temp = df[df['user'] != 'group_notification']
    temp = temp[temp['message'] != '<Media omitted>\n']

    def remove_stop_words(message):
        y = []
        for word in message.lower().split():
            if word not in stop_words:
                y.append(word)
        return " ".join(y)

    wc = WordCloud(width=500,height=500,min_font_size=10,background_color='white')
    temp['message'] = temp['message'].apply(remove_stop_words)
    df_wc = wc.generate(temp['message'].str.cat(sep=" "))
    return df_wc

def most_common_words(selected_user,df):

    f = open('stop_hinglish.txt','r')
    stop_words = f.read()

    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    temp = df[df['user'] != 'group_notification']
    temp = temp[temp['message'] != '<Media omitted>\n']

    words = []

    for message in temp['message']:
        for word in message.lower().split():
            if word not in stop_words:
                words.append(word)

    most_common_df = pd.DataFrame(Counter(words).most_common(20))
    return most_common_df

def emoji_helper(selected_user, df):
    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    emojis = []
    for message in df['message']:
        # Using emoji v2.0+ syntax
        emojis.extend([c for c in message if c in emoji.EMOJI_DATA])

    emoji_df = pd.DataFrame(Counter(emojis).most_common(len(Counter(emojis))))
    return emoji_df

def monthly_timeline(selected_user,df):
    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    # Convert date strings to datetime objects with 2-digit year format
    df['date'] = pd.to_datetime(df['date'], format='%d/%m/%y')
    
    # Extract year and month information
    df['year'] = df['date'].dt.year
    df['month'] = df['date'].dt.month_name()
    df['month_num'] = df['date'].dt.month
    
    timeline = df.groupby(['year', 'month_num', 'month']).count()['message'].reset_index()

    # Create formatted month-year strings
    timeline['time'] = timeline.apply(lambda row: f"{row['month'][:3]}-{row['year']}", axis=1)

    return timeline

def daily_timeline(selected_user,df):

    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    daily_timeline = df.groupby('only_date').count()['message'].reset_index()

    return daily_timeline

def week_activity_map(selected_user,df):

    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    return df['day_name'].value_counts()

def month_activity_map(selected_user,df):

    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    return df['month'].value_counts()

def activity_heatmap(selected_user,df):

    if selected_user != 'Overall':
        df = df[df['user'] == selected_user]

    user_heatmap = df.pivot_table(index='day_name', columns='period', values='message', aggfunc='count').fillna(0)

    return user_heatmap

def detect_phishing(message):
    extract = URLExtract()
    urls = extract.find_urls(message)
    
    malicious = []
    for url in urls:
        # Use VirusTotal API
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        if response.json().get('positives', 0) > 0:
            malicious.append(url)
    return malicious

def find_sensitive_data(message):
    credit_card = re.findall(r'\b(?:\d[ -]*?){13,16}\b', message)
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', message)
    return len(credit_card) + len(emails)

def calculate_threat_score(df):
    # Existing code
    score = 0
    score += len(df[df['message'].str.contains('password|login|credential', case=False)]) * 2
    score += df['sensitive_data'].sum() * 5
    
    # Add these for comprehensive scoring
    score += len(df[df['message'].str.contains('http://|https://')]) * 1  # URL count
    score += len(df[df['message'].str.contains('<Media omitted>')]) * 0.5  # Media risk
    return min(10, score // 10)  # Cap at 10















