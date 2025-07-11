from google.oauth2 import service_account
from googleapiclient.discovery import build
import io
from googleapiclient.http import MediaIoBaseDownload

SERVICE_ACCOUNT_FILE = 'service_account.json'
SCOPES = ['https://www.googleapis.com/auth/drive']

creds = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES)
drive_service = build('drive', 'v3', credentials=creds)

def download_file_bytes(file_id):
    fh = io.BytesIO()
    request = drive_service.files().get_media(fileId=file_id)
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        status, done = downloader.next_chunk()
    fh.seek(0)
    return fh.read()

def share_folder(folder_id, email):
    """Shares the folder with the specified email (Viewer access)."""
    try:
        permission = {
            'type': 'user',
            'role': 'writer',  # or 'writer' if needed
            'emailAddress': email
        }

        result = drive_service.permissions().create(
            fileId=folder_id,
            body=permission,
            fields='id',
            sendNotificationEmail=False
        ).execute()

        print(f"✅ Folder {folder_id} shared with {email}, permission ID: {result.get('id')}")
    except Exception as e:
        print(f"❌ Failed to share folder with {email}: {str(e)}")

def get_folder_id(name, parent_id=None):
    query = f"name = '{name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    if parent_id:
        query += f" and '{parent_id}' in parents"

    results = drive_service.files().list(q=query, fields="files(id)").execute()
    folders = results.get('files', [])
    return folders[0]['id'] if folders else None

def list_screenshots(folder_id):
    results = drive_service.files().list(
        q=f"'{folder_id}' in parents and mimeType contains 'image/' and trashed = false",
        fields="files(id, name, webViewLink, thumbnailLink)"
    ).execute()

    return [
        {
            'id': f['id'],                  # <-- This line is newly added
            'name': f['name'],
            'webViewLink': f['webViewLink'],
            'thumbnailLink': f['thumbnailLink']
        }
        for f in results.get('files', [])
    ]

def create_overseer_folder(overseer_code):
    root_folder_id = '1O0JY4jHqx3XT4c6n0-awgipjNFdiDziD'  # Replace with your actual ID
    folder_metadata = {
        'name': overseer_code,
        'mimeType': 'application/vnd.google-apps.folder',
        'parents': [root_folder_id]
    }
    created = drive_service.files().create(body=folder_metadata, fields='id').execute()
    return created.get('id')