from google.oauth2 import service_account
from googleapiclient.discovery import build
import os
from googleapiclient.http import MediaFileUpload

SERVICE_ACCOUNT_FILE = 'service_account.json'  # Your downloaded key
SCOPES = ['https://www.googleapis.com/auth/drive']

creds = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES)
drive_service = build('drive', 'v3', credentials=creds)

def create_or_get_folder(name, parent_id=None):
    # Check if folder already exists
    query = f"name='{name}' and mimeType='application/vnd.google-apps.folder'"
    if parent_id:
        query += f" and '{parent_id}' in parents"

    results = drive_service.files().list(q=query,
                                         spaces='drive',
                                         fields='files(id, name)').execute()
    items = results.get('files', [])

    if items:
        return items[0]['id']

    file_metadata = {
        'name': name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    if parent_id:
        file_metadata['parents'] = [parent_id]

    folder = drive_service.files().create(body=file_metadata,
                                          fields='id').execute()
    return folder.get('id')

def upload_file(file_path, parent_folder_id):
    file_name = os.path.basename(file_path)
    file_metadata = {
        'name': file_name,
        'parents': [parent_folder_id]
    }
    media = MediaFileUpload(file_path, resumable=True)
    file = drive_service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()
    return file.get('id')