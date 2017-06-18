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

app = Flask(__name__)
app.config['SECRET_KEY'] = str(uuid.uuid4())

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


def get_credential():
    if not is_signed_in():
        return None
    credentials = client.OAuth2Credentials.from_json(session['credentials'])
    if credentials.access_token_expired:
        return None
    return credentials


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
    app.logger.error('An error occurred when getting user info: %s', e)
  if user_info and user_info.get('id'):
    return user_info
  else:
    return None


def upload_to_Drive(file_dict, folder_id):
    credentials = get_credential()
    if credentials is None:
        return None
    http = credentials.authorize(httplib2.Http())
    drive_service = discovery.build('drive', 'v3', http=http)
    links = {}
    for email, file_path in file_dict.iteritems():
        file_metadata = { 'name': os.path.basename(file_path),
                          'parents': [folder_id] }
        if not folder_id:
            del file_metadata['parents']
        media = MediaFileUpload(file_path, mimetype='image/png')
        file = drive_service.files().create(body=file_metadata,
                                            media_body=media,
                                            fields='webViewLink').execute()
        links[email] = file.get('webViewLink')
    return links


def remove_files(files):
    for f in files:
        try:
            os.remove(f)
        except OSError as err:
            app.logger.error("Error occured when trying to delete %s\n%s"
                              % (f, err))


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
    credentials = get_credential()
    if credentials is not None:
        credentials.revoke(httplib2.Http())
    session.clear()
    flash(u"Signed out successfully!", 'success')
    return redirect(url_for('index'))


@app.route('/generate', methods=['POST'])
def generate():
    if not is_signed_in():
        flash(u'You need to sign in first', 'warning')
        return redirect(url_for('index'))
    
    emailsStr = request.form['emails']
    folder_id = request.form['folder_id']

    emails_raw = emailsStr.split("\n")
    emails = []
    for e in emails_raw:
        e = sanitize_email(e)
        if is_valid_email(e):
            emails.append(e)

    app.logger.info("Received %d emails. Generating QR codes..." % (len(emails)))
    if not os.path.isdir(QR_IMAGE_DIR):
        os.makedirs(QR_IMAGE_DIR)
        app.logger.info("Created directory %s" % (QR_IMAGE_DIR))

    count_generated = 0
    file_dict = {}
    for e in emails:
        file_name = email_to_filename(e)
        if len(file_name) == 0:
            continue

        img_qr = qrcode.make(e)

        file_path = os.path.join(QR_IMAGE_DIR, file_name)
        try:
            img_qr.save(file_path)
            file_dict[e] = file_path
            count_generated += 1
        except IOError:
            app.logger.error("Cannot create %s" % (file_name))
    
    app.logger.info("Generated %d QR code" % (count_generated))
    app.logger.debug("Uploading QR code to Drive")

    try:
        email_link = upload_to_Drive(file_dict, folder_id)
    except errors.HttpError as err:
        flash("Error while uploading to Google Drive: %s" % (err), 'danger')
        remove_files(file_dict.values())
        return redirect(url_for('index'))

    app.logger.info("Finished uploading QR code to Drive")

    remove_files(file_dict.values())
    
    invalid_emails = len(emails_raw) - len(emails)
    flash(u'QR code generated and uploaded to Google Drive. ' +\
          u'Removed %d invalid emails' % (invalid_emails), 'success')
    return redirect(url_for('index', email_link=json.dumps(email_link),
                                     prev_folder_id=folder_id))


@app.errorhandler(500)
def server_error(e):
    app.logger.exception('An error occurred during a request.')
    return """
    An internal error occurred: <pre>{}</pre>
    See logs for full stacktrace.
    """.format(e), 500


if __name__ == '__main__':
    app.logger.setLevel(logging.DEBUG)
    # This is used when running locally. Gunicorn is used to run the
    # application on Google App Engine. See entrypoint in app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)