import os
import httplib2
import logging
import qrcode
import uuid
import json
import re

from flask import Flask, render_template, request, session, url_for, \
    redirect, flash
from oauth2client import client
from apiclient import discovery
from googleapiclient.http import MediaFileUpload
from googleapiclient import errors

MODE = os.getenv('VAQR_MODE', 'dev')
if MODE == 'dev':
    import config_dev as config
elif MODE =='prod':
    import config_prod as config

app = Flask(__name__)
app.config.from_object(config)

logger = logging.getLogger("main.py")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

logger.info('Current mode: ' + MODE)

QR_IMAGE_DIR = "qr-images"
IMAGE_EXTENSION = "png"
SCOPES = ('https://www.googleapis.com/auth/drive '
          'https://www.googleapis.com/auth/userinfo.email ')


def sanitize_email(e):
    e = e.replace('\r', '')
    e = e.replace(' ', '')
    return e    


def email_to_filename(e):
    e = sanitize_email(e)
    e = e.replace("@", "-at-")    
    return e + "." + IMAGE_EXTENSION


def is_signed_in():
    return 'credentials' in session


def is_valid_email(e):
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return len(e) > 7 and re.match(pattern, e) != None


def get_credentials():
    if not is_signed_in():
        return None
    credentials = client.OAuth2Credentials.from_json(session['credentials'])
    if credentials.access_token_expired:
        return None
    return credentials


def clear_credentials():
    try:
        credentials = get_credentials()
        if credentials is not None:
            credentials.revoke(httplib2.Http())
    except Exception as err:
        logger.error('Invalid credential')
    session.clear()


def get_user_info(credentials):
  """Send a request to the UserInfo API to retrieve the user's information.

  Args:
    credentials: oauth2client.client.OAuth2Credentials instance to authorize the
                 request.
  Returns:
    User information as a dict.
  """
  user_info_service = discovery.build(
      serviceName='oauth2', version='v2',
      http=credentials.authorize(httplib2.Http()))
  user_info = None
  try:
    user_info = user_info_service.userinfo().get().execute()
  except errors.HttpError as e:
    logger.error('An error occurred when getting user info: %s', e)
  if user_info and user_info.get('id'):
    return user_info
  else:
    return None


def upload_to_Drive(email_file, folder_id):
    credentials = get_credentials()
    if credentials is None:
        raise client.HttpAccessTokenRefreshError
    http = credentials.authorize(httplib2.Http())
    drive_service = discovery.build('drive', 'v3', http=http)
    links = []
    for email, file_path in email_file:
        link = ''
        if os.path.exists(file_path):
            file_metadata = { 'name': os.path.basename(file_path),
                            'parents': [folder_id] }
            if not folder_id:
                del file_metadata['parents']
            media = MediaFileUpload(file_path, mimetype='image/png')
            file = drive_service.files().create(body=file_metadata,
                                                media_body=media,
                                                fields='webViewLink').execute()
            link = file.get('webViewLink')
        links.append((email, link))
    return links


def remove_files(files):
    for f in files:
        try:
            os.remove(f)
        except OSError as err:
            logger.error(err)


@app.route('/')
def index():
    email = session.get('email', '')
    email_link_json = request.args.get('email_link', '{}')
    email_link = json.loads(email_link_json)
    prev_folder_id = request.args.get('prev_folder_id', '')
    return render_template('index.html', email=email, 
                                         is_signed_in=is_signed_in(),
                                         email_link=email_link,
                                         prev_folder_id=prev_folder_id)


@app.route('/oauth2callback')
def oauth2callback():
    scheme = 'http' if app.debug else 'https'
    flow = client.flow_from_clientsecrets(
        'client_secret.json',
        scope=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True, _scheme=scheme))
    flow.params['access_type'] = 'offline'           # offline access
    flow.params['include_granted_scopes'] = 'true'   # incremental auth
    if 'code' not in request.args:
        auth_uri = flow.step1_get_authorize_url()
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        user_info = get_user_info(credentials)
        session['credentials'] = credentials.to_json()
        session['email'] = user_info['email']
        flash(u'Signed in successfully!', 'success')
        return redirect(url_for('index'))


@app.route('/oauth2revoke')
def oauth2revoke():
    clear_credentials()
    flash(u"Signed out successfully!", 'success')
    return redirect(url_for('index'))


@app.route('/generate', methods=['POST'])
def generate():
    if not is_signed_in():
        flash(u'You need to sign in first', 'warning')
        return redirect(url_for('index'))

    emailsStr = request.form['emails'].strip()
    folder_id = request.form['folder_id'].strip()
    
    if len(emailsStr) == 0:
        flash(u'Please enter at least 1 email address', 'warning')
        return redirect(url_for('index'))

    emails = emailsStr.split("\n")

    logger.info("Received %d emails. Generating QR codes..." % (len(emails)))
    if not os.path.isdir(QR_IMAGE_DIR):
        os.makedirs(QR_IMAGE_DIR)
        logger.info("Created directory %s" % (QR_IMAGE_DIR))

    count_generated = 0
    email_file = []
    for e in emails:
        if not is_valid_email(sanitize_email(e)):
            email_file.append((e, ''))
            continue

        file_name = email_to_filename(e)
        img_qr = qrcode.make(e)

        file_path = os.path.join(QR_IMAGE_DIR, file_name)
        try:
            img_qr.save(file_path)
            email_file.append((e, file_path))
            count_generated += 1
        except IOError:
            logger.error("Cannot create %s" % (file_name))
    
    logger.info("Generated %d QR code" % (count_generated))
    logger.debug("Uploading QR code to Drive")

    try:
        email_link = upload_to_Drive(email_file, folder_id)
    except errors.HttpError:
        remove_files([ef[1] for ef in email_file])
        flash('Error while uploading to Google Drive. Please check your folder ID.', 
              'danger')
        return redirect(url_for('index'))
    except client.HttpAccessTokenRefreshError:
        clear_credentials()
        remove_files([ef[1] for ef in email_file])
        flash('Authorization error. Please sign in again.', 'warning')
        return redirect(url_for('index'))        

    logger.info('Finished uploading QR code to Drive')

    remove_files([ef[1] for ef in email_file])

    flash(u'Generated and uploaded %d QR Codes. ' % (count_generated), 'success')
    return redirect(url_for('index', email_link=json.dumps(email_link),
                                     prev_folder_id=folder_id))


@app.errorhandler(500)
def server_error(e):
    logger.exception('An error occurred during a request.')
    return """
    An internal error occurred: <pre>{}</pre>
    See logs for full stacktrace.
    """.format(e), 500


if __name__ == '__main__':
    # This is used when running locally. Gunicorn is used to run the
    # application on Google App Engine. See entrypoint in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)